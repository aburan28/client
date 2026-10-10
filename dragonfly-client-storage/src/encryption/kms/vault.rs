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

//! The HashiCorp Vault transit key provider: the data keys are wrapped by the
//! `encrypt` and `decrypt` endpoints of a transit key, with a static token or
//! a token obtained from the Kubernetes auth method.

use super::http::{
    base64_decode, base64_encode, env_var, json_body, new_http_client, read_secret_file, send_json,
    str_field, u64_field, HttpError, Token, TokenCache,
};
use super::{bind_context, unbind_context, DataKey, KeyProvider, WrappedKey};
use async_trait::async_trait;
use dragonfly_client_config::dfdaemon::VaultTransit as VaultTransitConfig;
use dragonfly_client_core::{Error, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::info;
use zeroize::Zeroizing;

/// The authentication of the Vault client.
enum Auth {
    /// A static token.
    Token(Zeroizing<String>),

    /// A login with the Kubernetes auth method.
    Kubernetes {
        /// The mount path of the auth method.
        mount: String,

        /// The role to log in as.
        role: String,

        /// The path of the service account token of the pod.
        jwt_file: PathBuf,
    },
}

/// VaultTransitKeyProvider wraps the data keys with a Vault transit key.
pub struct VaultTransitKeyProvider {
    /// The HTTP client.
    http: reqwest::Client,

    /// The address of the Vault server, without a trailing slash.
    address: String,

    /// The namespace of the Vault enterprise server.
    namespace: Option<String>,

    /// The mount path of the transit secrets engine.
    mount: String,

    /// The name of the transit key.
    key_name: String,

    /// The authentication of the client.
    auth: Auth,

    /// The cached token.
    tokens: TokenCache,
}

/// Implements the Vault transit key provider.
impl VaultTransitKeyProvider {
    /// Creates a new Vault transit key provider from the configuration and
    /// the `VAULT_ADDR`, `VAULT_NAMESPACE` and `VAULT_TOKEN` environment
    /// variables.
    pub async fn new(config: &VaultTransitConfig) -> Result<Self> {
        let address = config
            .address
            .clone()
            .or_else(|| env_var("VAULT_ADDR"))
            .ok_or_else(|| {
                Error::Encryption(
                    "storage.encryption.kms.vaultTransit.address or VAULT_ADDR is required"
                        .to_string(),
                )
            })?;
        let key_name = config.key_name.clone().ok_or_else(|| {
            Error::Encryption("storage.encryption.kms.vaultTransit.keyName is required".to_string())
        })?;

        let auth = if let Some(role) = &config.kubernetes_role {
            Auth::Kubernetes {
                mount: config.kubernetes_auth_mount.clone(),
                role: role.clone(),
                jwt_file: config.kubernetes_jwt_file.clone(),
            }
        } else if let Some(token_file) = &config.token_file {
            Auth::Token(read_secret_file(token_file).await?)
        } else if let Some(token) = env_var("VAULT_TOKEN") {
            Auth::Token(Zeroizing::new(token))
        } else {
            return Err(Error::Encryption(
                "storage.encryption.kms.vaultTransit needs kubernetesRole, tokenFile or VAULT_TOKEN"
                    .to_string(),
            ));
        };

        info!(
            "vault transit key provider uses key {}/{} at {}",
            config.mount, key_name, address
        );
        Ok(Self {
            http: new_http_client()?,
            address: address.trim_end_matches('/').to_string(),
            namespace: config
                .namespace
                .clone()
                .or_else(|| env_var("VAULT_NAMESPACE")),
            mount: config.mount.trim_matches('/').to_string(),
            key_name,
            auth,
            tokens: TokenCache::default(),
        })
    }

    /// Returns the identifier of the transit key.
    fn key_id(&self) -> String {
        format!("{}/{}", self.mount, self.key_name)
    }

    /// Returns the token, logging in when needed.
    async fn token(&self) -> Result<Zeroizing<String>> {
        self.tokens.get(|| self.login()).await
    }

    /// Logs in to Vault according to the authentication.
    async fn login(&self) -> Result<Token> {
        match &self.auth {
            Auth::Token(token) => Ok(Token::new(token.to_string(), None)),
            Auth::Kubernetes {
                mount,
                role,
                jwt_file,
            } => {
                let jwt = read_secret_file(jwt_file).await?;
                let response = send_json(json_body(
                    self.request(
                        reqwest::Method::POST,
                        &format!("{}/v1/auth/{}/login", self.address, mount.trim_matches('/')),
                        None,
                    ),
                    &json!({ "role": role, "jwt": jwt.as_str() }),
                ))
                .await
                .map_err(|err| err.into_error("vault kubernetes login"))?;

                let auth = response.get("auth").cloned().unwrap_or(Value::Null);
                let token = str_field(&auth, "client_token", "vault kubernetes login")?;
                Ok(Token::new(
                    token.to_string(),
                    u64_field(&auth, "lease_duration").filter(|lease| *lease > 0),
                ))
            }
        }
    }

    /// Builds a request to Vault with the namespace and the token headers.
    fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut request = self.http.request(method, url);
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }

        if let Some(token) = token {
            request = request.header("X-Vault-Token", token);
        }

        request
    }

    /// Calls the transit operation with the body, retrying once with a fresh
    /// token when the token is rejected.
    async fn transit(&self, operation: &str, body: Value) -> Result<Value> {
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.address, self.mount, operation, self.key_name
        );
        let what = format!("vault transit {operation}");

        let mut retried = false;
        loop {
            let token = self.token().await?;
            match send_json(json_body(
                self.request(reqwest::Method::POST, &url, Some(&token)),
                &body,
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

/// Implements the key provider for the Vault transit key provider.
#[async_trait]
impl KeyProvider for VaultTransitKeyProvider {
    /// Returns the name of the provider.
    fn name(&self) -> &'static str {
        "vaultTransit"
    }

    /// Returns the identifier of the transit key.
    fn active_key_id(&self) -> &str {
        &self.key_name
    }

    /// Wraps the data key bound to the context with the transit key.
    async fn wrap(&self, data_key: &DataKey, context: &[u8]) -> Result<WrappedKey> {
        let plaintext = bind_context(data_key, context);
        let response = self
            .transit("encrypt", json!({ "plaintext": base64_encode(&plaintext) }))
            .await?;

        let data = response.get("data").cloned().unwrap_or(Value::Null);
        let ciphertext = str_field(&data, "ciphertext", "vault transit encrypt")?;
        Ok(WrappedKey {
            key_id: self.key_id(),
            ciphertext: ciphertext.as_bytes().to_vec(),
        })
    }

    /// Unwraps the data key with the transit key, verifying the context.
    async fn unwrap(&self, wrapped_key: &WrappedKey, context: &[u8]) -> Result<DataKey> {
        if wrapped_key.key_id != self.key_id() {
            return Err(Error::Encryption(format!(
                "wrapped key of transit key {} does not match the configured key {}",
                wrapped_key.key_id,
                self.key_id()
            )));
        }

        let ciphertext = std::str::from_utf8(&wrapped_key.ciphertext)
            .map_err(|_| Error::Encryption("invalid vault transit ciphertext".to_string()))?;
        let response = self
            .transit("decrypt", json!({ "ciphertext": ciphertext }))
            .await?;

        let data = response.get("data").cloned().unwrap_or(Value::Null);
        let plaintext = base64_decode(
            str_field(&data, "plaintext", "vault transit decrypt")?,
            "vault transit plaintext",
        )?;
        unbind_context(&plaintext, context)
    }
}

/// Keeps the HTTP error type referenced for the retry logic documentation.
#[allow(dead_code)]
fn _is_http_error(err: &HttpError) -> bool {
    err.is_unauthorized()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::kms::KEY_LEN;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(server: &MockServer, dir: &std::path::Path) -> VaultTransitConfig {
        let token_file = dir.join("token");
        std::fs::write(&token_file, "s.token\n").unwrap();
        VaultTransitConfig {
            address: Some(format!("{}/", server.uri())),
            key_name: Some("dragonfly".to_string()),
            token_file: Some(token_file),
            namespace: Some("admin".to_string()),
            ..Default::default()
        }
    }

    async fn mount_transit(server: &MockServer, token: &str, plaintext: &str) {
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/dragonfly"))
            .and(header("X-Vault-Token", token))
            .and(header("X-Vault-Namespace", "admin"))
            .and(body_partial_json(json!({ "plaintext": plaintext })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "ciphertext": "vault:v1:abc" }
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/dragonfly"))
            .and(header("X-Vault-Token", token))
            .and(body_partial_json(json!({ "ciphertext": "vault:v1:abc" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "plaintext": plaintext }
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn test_vault_transit_wrap_unwrap_with_token() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let data_key = DataKey::new([7u8; KEY_LEN]);
        let plaintext = base64_encode(&bind_context(&data_key, b"context"));
        mount_transit(&server, "s.token", &plaintext).await;

        let provider = VaultTransitKeyProvider::new(&config(&server, dir.path()))
            .await
            .unwrap();
        assert_eq!(provider.active_key_id(), "dragonfly");

        let wrapped = provider.wrap(&data_key, b"context").await.unwrap();
        assert_eq!(wrapped.key_id, "transit/dragonfly");
        assert_eq!(wrapped.ciphertext, b"vault:v1:abc");

        let unwrapped = provider.unwrap(&wrapped, b"context").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());

        // Another context does not verify, and another key is refused
        // without a request.
        assert!(provider.unwrap(&wrapped, b"other").await.is_err());
        let other = WrappedKey {
            key_id: "transit/other".to_string(),
            ciphertext: wrapped.ciphertext.clone(),
        };
        assert!(provider.unwrap(&other, b"context").await.is_err());
    }

    #[tokio::test]
    async fn test_vault_transit_kubernetes_login_and_retry() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let jwt_file = dir.path().join("jwt");
        std::fs::write(&jwt_file, "eyJhbGciOi").unwrap();

        let data_key = DataKey::new([9u8; KEY_LEN]);
        let plaintext = base64_encode(&bind_context(&data_key, b"ctx"));

        // The first login yields a token the server then revokes, the retry
        // logs in again.
        Mock::given(method("POST"))
            .and(path("/v1/auth/k8s/login"))
            .and(body_partial_json(
                json!({ "role": "dragonfly", "jwt": "eyJhbGciOi" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": "hvs.revoked", "lease_duration": 3600 }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/k8s/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": "hvs.fresh", "lease_duration": "3600" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/dragonfly"))
            .and(header("X-Vault-Token", "hvs.revoked"))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&server)
            .await;
        mount_transit(&server, "hvs.fresh", &plaintext).await;

        let config = VaultTransitConfig {
            address: Some(server.uri()),
            key_name: Some("dragonfly".to_string()),
            kubernetes_role: Some("dragonfly".to_string()),
            kubernetes_auth_mount: "k8s".to_string(),
            kubernetes_jwt_file: jwt_file,
            namespace: Some("admin".to_string()),
            ..Default::default()
        };
        let provider = VaultTransitKeyProvider::new(&config).await.unwrap();
        let wrapped = provider.wrap(&data_key, b"ctx").await.unwrap();
        let unwrapped = provider.unwrap(&wrapped, b"ctx").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());
    }

    #[tokio::test]
    async fn test_vault_transit_errors() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/dragonfly"))
            .respond_with(ResponseTemplate::new(500).set_body_string("sealed"))
            .mount(&server)
            .await;

        let provider = VaultTransitKeyProvider::new(&config(&server, dir.path()))
            .await
            .unwrap();
        let err = provider
            .wrap(&DataKey::new([1u8; KEY_LEN]), b"ctx")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("status 500"), "{err}");

        // Missing address, key or token.
        assert!(VaultTransitKeyProvider::new(&VaultTransitConfig {
            key_name: Some("k".to_string()),
            ..Default::default()
        })
        .await
        .is_err());
        assert!(VaultTransitKeyProvider::new(&VaultTransitConfig {
            address: Some(server.uri()),
            key_name: Some("k".to_string()),
            token_file: Some(dir.path().join("missing")),
            ..Default::default()
        })
        .await
        .is_err());
    }
}
