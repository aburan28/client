/*
 *     Copyright 2025 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! The Google Cloud KMS key provider: the data keys are wrapped by the
//! `encrypt` and `decrypt` methods of a symmetric crypto key, with the
//! context as additional authenticated data, and a token of a service
//! account key or of the metadata server.

use super::http::{
    base64_decode, base64_encode, base64url_encode, env_var, json_body, new_http_client, send_json,
    str_field, u64_field, unix_now, Token, TokenCache,
};
use super::{context_digest_hex, DataKey, KeyProvider, WrappedKey, KEY_LEN};
use async_trait::async_trait;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use dragonfly_client_config::dfdaemon::GcpKms as GcpKmsConfig;
use dragonfly_client_core::{Error, Result};
use serde_json::{json, Value};
use std::path::Path;
use tracing::info;
use zeroize::Zeroizing;

/// The OAuth scope of the Cloud KMS API.
const CLOUD_KMS_SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";

/// The default host of the metadata server.
const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";

/// The lifetime of the service account assertions in seconds.
const ASSERTION_LIFETIME: u64 = 3600;

/// The token source of the Cloud KMS client.
pub enum TokenSource {
    /// A service account key exchanged for a token.
    ServiceAccount(ServiceAccountKey),

    /// The metadata server of the instance or the GKE workload identity.
    Metadata {
        /// The host of the metadata server.
        host: String,
    },
}

/// ServiceAccountKey is the service account key file.
pub struct ServiceAccountKey {
    /// The email of the service account.
    client_email: String,

    /// The token endpoint.
    token_uri: String,

    /// The PKCS#8 private key of the service account.
    private_key: KeyPair,
}

/// Implements the service account key.
impl ServiceAccountKey {
    /// Parses the service account key file.
    pub fn parse(content: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(content)
            .map_err(|err| Error::Encryption(format!("invalid service account key file: {err}")))?;

        let client_email = str_field(&value, "client_email", "service account key")?.to_string();
        let token_uri = value
            .get("token_uri")
            .and_then(Value::as_str)
            .unwrap_or("https://oauth2.googleapis.com/token")
            .to_string();

        let pem =
            Zeroizing::new(str_field(&value, "private_key", "service account key")?.to_string());
        let der = match rustls_pemfile::private_key(&mut pem.as_bytes()) {
            Ok(Some(rustls_pki_types::PrivateKeyDer::Pkcs8(der))) => der,
            _ => {
                return Err(Error::Encryption(
                    "service account key file has no PKCS#8 private key".to_string(),
                ))
            }
        };
        let private_key = KeyPair::from_pkcs8(der.secret_pkcs8_der()).map_err(|err| {
            Error::Encryption(format!("invalid service account private key: {err}"))
        })?;

        Ok(Self {
            client_email,
            token_uri,
            private_key,
        })
    }

    /// Signs the JWT assertion requesting a token for the Cloud KMS scope.
    fn assertion(&self, now: u64) -> Result<String> {
        let header = base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = base64url_encode(
            json!({
                "iss": self.client_email,
                "scope": CLOUD_KMS_SCOPE,
                "aud": self.token_uri,
                "iat": now,
                "exp": now + ASSERTION_LIFETIME,
            })
            .to_string()
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");

        let mut signature = vec![0u8; self.private_key.public_modulus_len()];
        self.private_key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::Encryption("sign service account assertion failed".to_string()))?;

        Ok(format!("{signing_input}.{}", base64url_encode(&signature)))
    }
}

/// GcpKmsKeyProvider wraps the data keys with a Cloud KMS crypto key.
pub struct GcpKmsKeyProvider {
    /// The HTTP client.
    http: reqwest::Client,

    /// The endpoint of the Cloud KMS API, without a trailing slash.
    endpoint: String,

    /// The resource name of the crypto key.
    key_name: String,

    /// The token source.
    token_source: TokenSource,

    /// The cached token.
    tokens: TokenCache,
}

/// Implements the Cloud KMS key provider.
impl GcpKmsKeyProvider {
    /// Creates a new Cloud KMS key provider from the configuration and the
    /// `GOOGLE_APPLICATION_CREDENTIALS` and `GCE_METADATA_HOST` environment
    /// variables.
    pub async fn new(config: &GcpKmsConfig) -> Result<Self> {
        let key_name = config.key_name.clone().ok_or_else(|| {
            Error::Encryption("storage.encryption.kms.gcpKms.keyName is required".to_string())
        })?;

        let credentials_file = config
            .credentials_file
            .clone()
            .or_else(|| env_var("GOOGLE_APPLICATION_CREDENTIALS").map(Into::into));
        let token_source = match credentials_file {
            Some(path) => TokenSource::ServiceAccount(Self::read_service_account_key(&path).await?),
            None => TokenSource::Metadata {
                host: env_var("GCE_METADATA_HOST")
                    .unwrap_or_else(|| DEFAULT_METADATA_HOST.to_string()),
            },
        };

        info!(
            "gcp kms key provider uses key {} with the {} credentials",
            key_name,
            match token_source {
                TokenSource::ServiceAccount(_) => "service account key",
                TokenSource::Metadata { .. } => "metadata server",
            }
        );
        Self::with_token_source(&config.endpoint, key_name, token_source)
    }

    /// Creates a new Cloud KMS key provider with the token source.
    pub fn with_token_source(
        endpoint: &str,
        key_name: String,
        token_source: TokenSource,
    ) -> Result<Self> {
        Ok(Self {
            http: new_http_client()?,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            key_name,
            token_source,
            tokens: TokenCache::default(),
        })
    }

    /// Reads the service account key file.
    async fn read_service_account_key(path: &Path) -> Result<ServiceAccountKey> {
        let content = Zeroizing::new(tokio::fs::read(path).await.map_err(|err| {
            Error::Encryption(format!("read service account key {path:?} failed: {err}"))
        })?);
        ServiceAccountKey::parse(&content)
    }

    /// Returns the token, acquiring it when needed.
    async fn token(&self) -> Result<Zeroizing<String>> {
        self.tokens.get(|| self.acquire_token()).await
    }

    /// Acquires a token according to the token source.
    async fn acquire_token(&self) -> Result<Token> {
        let response = match &self.token_source {
            TokenSource::ServiceAccount(key) => {
                let assertion = key.assertion(unix_now())?;
                send_json(self.http.post(&key.token_uri).form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", assertion.as_str()),
                ]))
                .await
            }
            TokenSource::Metadata { host } => {
                send_json(
                    self.http
                        .get(format!(
                        "http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
                    ))
                        .header("Metadata-Flavor", "Google"),
                )
                .await
            }
        }
        .map_err(|err| err.into_error("gcp token request"))?;

        Ok(Token::new(
            str_field(&response, "access_token", "gcp token")?.to_string(),
            u64_field(&response, "expires_in"),
        ))
    }

    /// Calls the method of the crypto key with the body, retrying once with a
    /// fresh token when the token is rejected.
    async fn call(&self, resource: &str, method: &str, body: &Value) -> Result<Value> {
        let url = format!("{}/v1/{}:{}", self.endpoint, resource, method);
        let what = format!("gcp kms {method}");

        let mut retried = false;
        loop {
            let token = self.token().await?;
            match send_json(json_body(
                self.http.post(&url).bearer_auth(token.as_str()),
                body,
            ))
            .await
            {
                Ok(response) => return Ok(response),
                Err(err) if err.is_unauthorized() && !retried => {
                    self.tokens.invalidate().await;
                    retried = true;
                }
                Err(err) => return Err(err.into_error(&what)),
            }
        }
    }
}

/// Implements the key provider for the Cloud KMS key provider.
#[async_trait]
impl KeyProvider for GcpKmsKeyProvider {
    /// Returns the name of the provider.
    fn name(&self) -> &'static str {
        "gcpKms"
    }

    /// Returns the resource name of the crypto key.
    fn active_key_id(&self) -> &str {
        &self.key_name
    }

    /// Wraps the data key with the primary version of the crypto key, with the
    /// context as additional authenticated data, returning the resource name
    /// of the version used.
    async fn wrap(&self, data_key: &DataKey, context: &[u8]) -> Result<WrappedKey> {
        let response = self
            .call(
                &self.key_name,
                "encrypt",
                &json!({
                    "plaintext": base64_encode(data_key.as_ref()),
                    "additionalAuthenticatedData": base64_encode(context),
                }),
            )
            .await?;

        let name = str_field(&response, "name", "gcp kms encrypt")?;
        let ciphertext = str_field(&response, "ciphertext", "gcp kms encrypt")?;
        Ok(WrappedKey {
            key_id: name.to_string(),
            ciphertext: base64_decode(ciphertext, "gcp kms ciphertext")?.to_vec(),
        })
    }

    /// Unwraps the data key with the crypto key, which selects the version
    /// from the ciphertext, verifying the context as additional authenticated
    /// data.
    async fn unwrap(&self, wrapped_key: &WrappedKey, context: &[u8]) -> Result<DataKey> {
        // The key version comes from the untrusted file header, so it is only
        // accepted as a version of the configured key, which the decrypt
        // request names, so the token is never sent for another key.
        let prefix = format!("{}/cryptoKeyVersions/", self.key_name);
        if !wrapped_key.key_id.starts_with(&prefix) {
            return Err(Error::Encryption(format!(
                "wrapped key of key version {} is not a version of the configured key {}",
                wrapped_key.key_id, self.key_name
            )));
        }

        let response = self
            .call(
                &self.key_name,
                "decrypt",
                &json!({
                    "ciphertext": base64_encode(&wrapped_key.ciphertext),
                    "additionalAuthenticatedData": base64_encode(context),
                }),
            )
            .await?;

        let plaintext = base64_decode(
            str_field(&response, "plaintext", "gcp kms decrypt")?,
            "gcp kms plaintext",
        )?;
        if plaintext.len() != KEY_LEN {
            return Err(Error::Encryption(
                "gcp kms decrypt returned an invalid data encryption key".to_string(),
            ));
        }

        let mut data_key = DataKey::new([0u8; KEY_LEN]);
        data_key.copy_from_slice(&plaintext);
        Ok(data_key)
    }
}

/// Keeps the context digest helper referenced for providers binding the
/// context by digest.
#[allow(dead_code)]
fn _context_digest(context: &[u8]) -> String {
    context_digest_hex(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::KeySize;
    use wiremock::matchers::{body_partial_json, body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEY_NAME: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k";

    /// Generates a service account key file with a fresh RSA key and the
    /// token endpoint of the mock server.
    fn service_account_key_file(server: &MockServer) -> String {
        let key_pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = key_pair.as_der().unwrap();
        let base64 = base64_encode(der.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in base64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");

        json!({
            "type": "service_account",
            "client_email": "dfdaemon@p.iam.gserviceaccount.com",
            "private_key": pem,
            "token_uri": format!("{}/token", server.uri()),
        })
        .to_string()
    }

    async fn mount_kms(server: &MockServer, token: &str, data_key: &DataKey, context: &[u8]) {
        Mock::given(method("POST"))
            .and(path(format!("/v1/{KEY_NAME}:encrypt")))
            .and(header("Authorization", format!("Bearer {token}")))
            .and(body_partial_json(json!({
                "plaintext": base64_encode(data_key.as_ref()),
                "additionalAuthenticatedData": base64_encode(context),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": format!("{KEY_NAME}/cryptoKeyVersions/3"),
                "ciphertext": base64_encode(b"wrapped"),
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/{KEY_NAME}:decrypt")))
            .and(header("Authorization", format!("Bearer {token}")))
            .and(body_partial_json(json!({
                "ciphertext": base64_encode(b"wrapped"),
                "additionalAuthenticatedData": base64_encode(context),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plaintext": base64_encode(data_key.as_ref()),
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn test_gcp_kms_wrap_unwrap_with_service_account() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_file = dir.path().join("sa.json");
        std::fs::write(&credentials_file, service_account_key_file(&server)).unwrap();

        let data_key = DataKey::new([3u8; KEY_LEN]);
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("jwt-bearer"))
            .and(body_string_contains(
                "assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "ya29.token", "expires_in": 3599, "token_type": "Bearer"
            })))
            .mount(&server)
            .await;
        mount_kms(&server, "ya29.token", &data_key, b"context").await;

        let config = GcpKmsConfig {
            key_name: Some(KEY_NAME.to_string()),
            credentials_file: Some(credentials_file),
            endpoint: format!("{}/", server.uri()),
        };
        let provider = GcpKmsKeyProvider::new(&config).await.unwrap();
        assert_eq!(provider.active_key_id(), KEY_NAME);

        let wrapped = provider.wrap(&data_key, b"context").await.unwrap();
        assert_eq!(wrapped.key_id, format!("{KEY_NAME}/cryptoKeyVersions/3"));
        assert_eq!(wrapped.ciphertext, b"wrapped");

        let unwrapped = provider.unwrap(&wrapped, b"context").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());

        // Another context is not served by the mock, like the real service
        // rejecting the additional authenticated data.
        assert!(provider.unwrap(&wrapped, b"other").await.is_err());

        // A version of another key is refused without a request.
        let other = WrappedKey {
            key_id: "projects/p/locations/l/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1"
                .to_string(),
            ciphertext: wrapped.ciphertext.clone(),
        };
        assert!(provider.unwrap(&other, b"context").await.is_err());
    }

    #[tokio::test]
    async fn test_gcp_kms_metadata_token_and_retry() {
        let server = MockServer::start().await;
        let data_key = DataKey::new([4u8; KEY_LEN]);

        // The metadata server hands out a stale token first.
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .and(header("Metadata-Flavor", "Google"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "stale", "expires_in": 3600
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "valid", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/{KEY_NAME}:encrypt")))
            .and(header("Authorization", "Bearer stale"))
            .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
            .mount(&server)
            .await;
        mount_kms(&server, "valid", &data_key, b"ctx").await;

        let host = server.uri().trim_start_matches("http://").to_string();
        let provider = GcpKmsKeyProvider::with_token_source(
            &server.uri(),
            KEY_NAME.to_string(),
            TokenSource::Metadata { host },
        )
        .unwrap();

        let wrapped = provider.wrap(&data_key, b"ctx").await.unwrap();
        let unwrapped = provider.unwrap(&wrapped, b"ctx").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());
    }

    #[tokio::test]
    async fn test_gcp_kms_errors() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();

        // An invalid service account key file.
        let invalid = dir.path().join("invalid.json");
        std::fs::write(
            &invalid,
            r#"{"client_email": "a@b", "private_key": "nope"}"#,
        )
        .unwrap();
        assert!(GcpKmsKeyProvider::new(&GcpKmsConfig {
            key_name: Some(KEY_NAME.to_string()),
            credentials_file: Some(invalid),
            ..Default::default()
        })
        .await
        .is_err());
        assert!(GcpKmsKeyProvider::new(&GcpKmsConfig::default())
            .await
            .is_err());

        // A short plaintext from the service is rejected.
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "t", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/{KEY_NAME}:decrypt")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plaintext": base64_encode(b"short"),
            })))
            .mount(&server)
            .await;
        let host = server.uri().trim_start_matches("http://").to_string();
        let provider = GcpKmsKeyProvider::with_token_source(
            &server.uri(),
            KEY_NAME.to_string(),
            TokenSource::Metadata { host },
        )
        .unwrap();
        let wrapped = WrappedKey {
            key_id: format!("{KEY_NAME}/cryptoKeyVersions/1"),
            ciphertext: vec![1],
        };
        assert!(provider.unwrap(&wrapped, b"ctx").await.is_err());
    }
}
