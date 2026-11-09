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

//! The Azure Key Vault key provider: the data keys are wrapped by the
//! `wrapKey` and `unwrapKey` operations of a key of a key vault or a managed
//! HSM, with a token of the workload identity, the client secret or the
//! managed identity.

use super::http::{
    base64url_decode, base64url_encode, env_var, json_body, new_http_client, read_secret_file,
    send_json, str_field, u64_field, Token, TokenCache,
};
use super::{bind_context, unbind_context, DataKey, KeyProvider, WrappedKey};
use async_trait::async_trait;
use dragonfly_client_config::dfdaemon::AzureKeyVault as AzureKeyVaultConfig;
use dragonfly_client_core::{Error, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::info;
use zeroize::Zeroizing;

/// The version of the Key Vault REST API.
const API_VERSION: &str = "7.4";

/// The default authority host of Microsoft Entra ID.
const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";

/// The endpoint of the instance metadata service for managed identities.
const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";

/// The scope of the key vault tokens.
const KEY_VAULT_SCOPE: &str = "https://vault.azure.net/.default";

/// The scope of the managed HSM tokens.
const MANAGED_HSM_SCOPE: &str = "https://managedhsm.azure.net/.default";

/// The credential of the identity calling the key vault.
enum Credential {
    /// The workload identity: a federated token file exchanged for a token.
    Federated {
        /// The authority host.
        authority: String,

        /// The tenant id.
        tenant_id: String,

        /// The client id.
        client_id: String,

        /// The path of the federated token file.
        token_file: PathBuf,
    },

    /// The client credentials: a client secret.
    ClientSecret {
        /// The authority host.
        authority: String,

        /// The tenant id.
        tenant_id: String,

        /// The client id.
        client_id: String,

        /// The client secret.
        secret: Zeroizing<String>,
    },

    /// The managed identity of the virtual machine or the pod.
    ManagedIdentity {
        /// The endpoint of the identity service.
        endpoint: String,

        /// The header authenticating to the identity service, when it is not
        /// the instance metadata service.
        header: Option<String>,

        /// The client id of a user-assigned identity.
        client_id: Option<String>,
    },
}

/// AzureKeyVaultKeyProvider wraps the data keys with an Azure Key Vault key.
pub struct AzureKeyVaultKeyProvider {
    /// The HTTP client.
    http: reqwest::Client,

    /// The URL of the vault, without a trailing slash.
    vault_url: String,

    /// The name of the key.
    key_name: String,

    /// The version of the key wrapping new data keys.
    key_version: Option<String>,

    /// The key wrapping algorithm.
    algorithm: String,

    /// The scope of the tokens.
    scope: String,

    /// The credential of the identity.
    credential: Credential,

    /// The cached token.
    tokens: TokenCache,
}

/// Implements the Azure Key Vault key provider.
impl AzureKeyVaultKeyProvider {
    /// Creates a new Azure Key Vault key provider from the configuration and
    /// the `AZURE_*` and `IDENTITY_*` environment variables.
    pub async fn new(config: &AzureKeyVaultConfig) -> Result<Self> {
        let vault_url = config
            .vault_url
            .clone()
            .ok_or_else(|| {
                Error::Encryption(
                    "storage.encryption.kms.azureKeyVault.vaultUrl is required".to_string(),
                )
            })?
            .trim_end_matches('/')
            .to_string();
        let key_name = config.key_name.clone().ok_or_else(|| {
            Error::Encryption(
                "storage.encryption.kms.azureKeyVault.keyName is required".to_string(),
            )
        })?;

        let scope = if vault_url
            .trim_start_matches("https://")
            .split('/')
            .next()
            .is_some_and(|host| host.ends_with("managedhsm.azure.net"))
        {
            MANAGED_HSM_SCOPE
        } else {
            KEY_VAULT_SCOPE
        };

        let authority = config
            .authority_host
            .clone()
            .or_else(|| env_var("AZURE_AUTHORITY_HOST"))
            .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_string())
            .trim_end_matches('/')
            .to_string();
        let tenant_id = config
            .tenant_id
            .clone()
            .or_else(|| env_var("AZURE_TENANT_ID"));
        let client_id = config
            .client_id
            .clone()
            .or_else(|| env_var("AZURE_CLIENT_ID"));
        let federated_token_file = config
            .federated_token_file
            .clone()
            .or_else(|| env_var("AZURE_FEDERATED_TOKEN_FILE").map(PathBuf::from));
        let client_secret = match &config.client_secret_file {
            Some(path) => Some(read_secret_file(path).await?),
            None => env_var("AZURE_CLIENT_SECRET").map(Zeroizing::new),
        };

        let credential = match (
            tenant_id,
            client_id.clone(),
            federated_token_file,
            client_secret,
        ) {
            (Some(tenant_id), Some(client_id), Some(token_file), _) => Credential::Federated {
                authority,
                tenant_id,
                client_id,
                token_file,
            },
            (Some(tenant_id), Some(client_id), None, Some(secret)) => Credential::ClientSecret {
                authority,
                tenant_id,
                client_id,
                secret,
            },
            _ => Credential::ManagedIdentity {
                endpoint: env_var("IDENTITY_ENDPOINT")
                    .unwrap_or_else(|| DEFAULT_IMDS_ENDPOINT.to_string()),
                header: env_var("IDENTITY_HEADER"),
                client_id,
            },
        };

        info!(
            "azure key vault key provider uses key {} of {} with the {} credential",
            key_name,
            vault_url,
            match credential {
                Credential::Federated { .. } => "workload identity",
                Credential::ClientSecret { .. } => "client secret",
                Credential::ManagedIdentity { .. } => "managed identity",
            }
        );
        Ok(Self {
            http: new_http_client()?,
            vault_url,
            key_name,
            key_version: config.key_version.clone(),
            algorithm: config.algorithm.clone(),
            scope: scope.to_string(),
            credential,
            tokens: TokenCache::default(),
        })
    }

    /// Returns the token, acquiring it when needed.
    async fn token(&self) -> Result<Zeroizing<String>> {
        self.tokens.get(|| self.acquire_token()).await
    }

    /// Acquires a token for the key vault according to the credential.
    async fn acquire_token(&self) -> Result<Token> {
        let response = match &self.credential {
            Credential::Federated {
                authority,
                tenant_id,
                client_id,
                token_file,
            } => {
                let assertion = read_secret_file(token_file).await?;
                send_json(
                    self.http
                        .post(format!("{authority}/{tenant_id}/oauth2/v2.0/token"))
                        .form(&[
                            ("grant_type", "client_credentials"),
                            ("client_id", client_id.as_str()),
                            ("scope", self.scope.as_str()),
                            (
                                "client_assertion_type",
                                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            ),
                            ("client_assertion", assertion.as_str()),
                        ]),
                )
                .await
            }
            Credential::ClientSecret {
                authority,
                tenant_id,
                client_id,
                secret,
            } => {
                send_json(
                    self.http
                        .post(format!("{authority}/{tenant_id}/oauth2/v2.0/token"))
                        .form(&[
                            ("grant_type", "client_credentials"),
                            ("client_id", client_id.as_str()),
                            ("scope", self.scope.as_str()),
                            ("client_secret", secret.as_str()),
                        ]),
                )
                .await
            }
            Credential::ManagedIdentity {
                endpoint,
                header,
                client_id,
            } => {
                let resource = self.scope.trim_end_matches("/.default");
                let mut query = vec![
                    (
                        "api-version",
                        if header.is_some() {
                            "2019-08-01"
                        } else {
                            "2018-02-01"
                        },
                    ),
                    ("resource", resource),
                ];
                if let Some(client_id) = client_id {
                    query.push(("client_id", client_id.as_str()));
                }

                let mut request = self.http.get(endpoint).query(&query);
                request = match header {
                    Some(header) => request.header("X-IDENTITY-HEADER", header),
                    None => request.header("Metadata", "true"),
                };
                send_json(request).await
            }
        }
        .map_err(|err| err.into_error("azure token request"))?;

        Ok(Token::new(
            str_field(&response, "access_token", "azure token")?.to_string(),
            u64_field(&response, "expires_in"),
        ))
    }

    /// Calls the key operation at the URL with the body, retrying once with a
    /// fresh token when the token is rejected.
    async fn key_operation(&self, url: &str, body: &Value, what: &str) -> Result<Value> {
        let mut retried = false;
        loop {
            let token = self.token().await?;
            match send_json(json_body(
                self.http
                    .post(url)
                    .query(&[("api-version", API_VERSION)])
                    .bearer_auth(token.as_str()),
                body,
            ))
            .await
            {
                Ok(response) => return Ok(response),
                Err(err) if err.is_unauthorized() && !retried => {
                    self.tokens.invalidate().await;
                    retried = true;
                }
                Err(err) => return Err(err.into_error(what)),
            }
        }
    }
}

/// Implements the key provider for the Azure Key Vault key provider.
#[async_trait]
impl KeyProvider for AzureKeyVaultKeyProvider {
    /// Returns the name of the provider.
    fn name(&self) -> &'static str {
        "azureKeyVault"
    }

    /// Returns the name of the key.
    fn active_key_id(&self) -> &str {
        &self.key_name
    }

    /// Wraps the data key bound to the context with the key, returning the
    /// key identifier of the key version used.
    async fn wrap(&self, data_key: &DataKey, context: &[u8]) -> Result<WrappedKey> {
        let mut url = format!("{}/keys/{}", self.vault_url, self.key_name);
        if let Some(version) = &self.key_version {
            url.push('/');
            url.push_str(version);
        }
        url.push_str("/wrapkey");

        let plaintext = bind_context(data_key, context);
        let response = self
            .key_operation(
                &url,
                &json!({ "alg": self.algorithm, "value": base64url_encode(&plaintext) }),
                "azure key vault wrapKey",
            )
            .await?;

        let kid = str_field(&response, "kid", "azure key vault wrapKey")?;
        let value = str_field(&response, "value", "azure key vault wrapKey")?;
        Ok(WrappedKey {
            key_id: kid.to_string(),
            ciphertext: base64url_decode(value, "azure key vault wrapped key")?.to_vec(),
        })
    }

    /// Unwraps the data key with the key version it was wrapped with,
    /// verifying the context.
    async fn unwrap(&self, wrapped_key: &WrappedKey, context: &[u8]) -> Result<DataKey> {
        // The key identifier comes from the untrusted file header, so it is
        // only accepted as a version of the configured key of the configured
        // vault, which also keeps the token from being sent elsewhere.
        let prefix = format!("{}/keys/{}/", self.vault_url, self.key_name);
        let version = wrapped_key
            .key_id
            .strip_prefix(&prefix)
            .filter(|version| {
                !version.is_empty() && version.chars().all(|c| c.is_ascii_alphanumeric())
            })
            .ok_or_else(|| {
                Error::Encryption(format!(
                    "wrapped key of key {} is not a version of the configured key {}",
                    wrapped_key.key_id, prefix
                ))
            })?;

        let response = self
            .key_operation(
                &format!("{prefix}{version}/unwrapkey"),
                &json!({ "alg": self.algorithm, "value": base64url_encode(&wrapped_key.ciphertext) }),
                "azure key vault unwrapKey",
            )
            .await?;

        let value = str_field(&response, "value", "azure key vault unwrapKey")?;
        let plaintext = base64url_decode(value, "azure key vault unwrapped key")?;
        unbind_context(&plaintext, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::kms::KEY_LEN;
    use wiremock::matchers::{
        body_partial_json, body_string_contains, header, method, path, query_param,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_azure_key_vault_wrap_unwrap_with_client_secret() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let secret_file = dir.path().join("secret");
        std::fs::write(&secret_file, "s3cret\n").unwrap();

        let data_key = DataKey::new([5u8; KEY_LEN]);
        let bound = base64url_encode(&bind_context(&data_key, b"context"));
        let kid = format!("{}/keys/dragonfly/abc123", server.uri());

        Mock::given(method("POST"))
            .and(path("/tenant/oauth2/v2.0/token"))
            .and(body_string_contains("client_secret=s3cret"))
            .and(body_string_contains("client_id=client"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok", "expires_in": 3599
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/dragonfly/wrapkey"))
            .and(query_param("api-version", API_VERSION))
            .and(header("Authorization", "Bearer tok"))
            .and(body_partial_json(
                json!({ "alg": "RSA-OAEP-256", "value": bound }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kid": kid, "value": base64url_encode(b"wrapped")
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/dragonfly/abc123/unwrapkey"))
            .and(header("Authorization", "Bearer tok"))
            .and(body_partial_json(
                json!({ "value": base64url_encode(b"wrapped") }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kid": kid, "value": bound
            })))
            .mount(&server)
            .await;

        let config = AzureKeyVaultConfig {
            vault_url: Some(format!("{}/", server.uri())),
            key_name: Some("dragonfly".to_string()),
            authority_host: Some(server.uri()),
            tenant_id: Some("tenant".to_string()),
            client_id: Some("client".to_string()),
            client_secret_file: Some(secret_file),
            ..Default::default()
        };
        let provider = AzureKeyVaultKeyProvider::new(&config).await.unwrap();
        assert!(matches!(
            provider.credential,
            Credential::ClientSecret { .. }
        ));
        assert_eq!(provider.scope, KEY_VAULT_SCOPE);

        let wrapped = provider.wrap(&data_key, b"context").await.unwrap();
        assert_eq!(wrapped.key_id, kid);
        assert_eq!(wrapped.ciphertext, b"wrapped");

        let unwrapped = provider.unwrap(&wrapped, b"context").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());
        assert!(provider.unwrap(&wrapped, b"other").await.is_err());

        // A key identifier of another vault or key is refused without a
        // request.
        for key_id in [
            "https://evil.example/keys/dragonfly/abc123".to_string(),
            format!("{}/keys/other/abc123", server.uri()),
            format!("{}/keys/dragonfly/../x", server.uri()),
            format!("{}/keys/dragonfly/", server.uri()),
        ] {
            let other = WrappedKey {
                key_id,
                ciphertext: wrapped.ciphertext.clone(),
            };
            assert!(provider.unwrap(&other, b"context").await.is_err());
        }
    }

    #[tokio::test]
    async fn test_azure_key_vault_managed_identity_and_retry() {
        let server = MockServer::start().await;
        let data_key = DataKey::new([6u8; KEY_LEN]);
        let bound = base64url_encode(&bind_context(&data_key, b"ctx"));
        let kid = format!("{}/keys/dragonfly/v2", server.uri());

        // The identity endpoint hands out an expired token first, then a
        // valid one on the retry.
        Mock::given(method("GET"))
            .and(path("/identity"))
            .and(query_param("api-version", "2019-08-01"))
            .and(query_param("resource", "https://managedhsm.azure.net"))
            .and(query_param("client_id", "user-assigned"))
            .and(header("X-IDENTITY-HEADER", "secret-header"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "stale", "expires_in": "3600"
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/identity"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "valid", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/dragonfly/v2/wrapkey"))
            .and(header("Authorization", "Bearer stale"))
            .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/dragonfly/v2/wrapkey"))
            .and(header("Authorization", "Bearer valid"))
            .and(body_partial_json(json!({ "alg": "A256KW" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kid": kid, "value": base64url_encode(b"w")
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/dragonfly/v2/unwrapkey"))
            .and(header("Authorization", "Bearer valid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kid": kid, "value": bound
            })))
            .mount(&server)
            .await;

        // The vault URL of a managed HSM selects the managed HSM scope; the
        // mock server stands in for it here.
        let config = AzureKeyVaultConfig {
            vault_url: Some(server.uri()),
            key_name: Some("dragonfly".to_string()),
            key_version: Some("v2".to_string()),
            algorithm: "A256KW".to_string(),
            client_id: Some("user-assigned".to_string()),
            ..Default::default()
        };
        let mut provider = AzureKeyVaultKeyProvider::new(&config).await.unwrap();
        provider.scope = MANAGED_HSM_SCOPE.to_string();
        provider.credential = Credential::ManagedIdentity {
            endpoint: format!("{}/identity", server.uri()),
            header: Some("secret-header".to_string()),
            client_id: Some("user-assigned".to_string()),
        };

        let wrapped = provider.wrap(&data_key, b"ctx").await.unwrap();
        assert_eq!(wrapped.key_id, kid);
        let unwrapped = provider.unwrap(&wrapped, b"ctx").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());
    }

    #[tokio::test]
    async fn test_azure_key_vault_federated_credential() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("federated");
        std::fs::write(&token_file, "federated-jwt").unwrap();

        Mock::given(method("POST"))
            .and(path("/tenant/oauth2/v2.0/token"))
            .and(body_string_contains("client_assertion=federated-jwt"))
            .and(body_string_contains("jwt-bearer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "fed", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/k/wrapkey"))
            .and(header("Authorization", "Bearer fed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kid": format!("{}/keys/k/1", server.uri()), "value": "AQ"
            })))
            .mount(&server)
            .await;

        let config = AzureKeyVaultConfig {
            vault_url: Some(server.uri()),
            key_name: Some("k".to_string()),
            authority_host: Some(format!("{}/", server.uri())),
            tenant_id: Some("tenant".to_string()),
            client_id: Some("client".to_string()),
            federated_token_file: Some(token_file),
            ..Default::default()
        };
        let provider = AzureKeyVaultKeyProvider::new(&config).await.unwrap();
        assert!(matches!(provider.credential, Credential::Federated { .. }));

        let wrapped = provider
            .wrap(&DataKey::new([1u8; KEY_LEN]), b"ctx")
            .await
            .unwrap();
        assert_eq!(wrapped.ciphertext, vec![1]);

        // A managed HSM URL selects the managed HSM scope.
        let config = AzureKeyVaultConfig {
            vault_url: Some("https://hsm.managedhsm.azure.net".to_string()),
            key_name: Some("k".to_string()),
            ..Default::default()
        };
        let provider = AzureKeyVaultKeyProvider::new(&config).await.unwrap();
        assert_eq!(provider.scope, MANAGED_HSM_SCOPE);
        assert!(matches!(
            provider.credential,
            Credential::ManagedIdentity { .. }
        ));

        assert!(
            AzureKeyVaultKeyProvider::new(&AzureKeyVaultConfig::default())
                .await
                .is_err()
        );
    }
}
