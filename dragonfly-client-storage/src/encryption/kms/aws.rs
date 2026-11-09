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

//! The AWS KMS key provider: the data keys are wrapped by the `Encrypt` and
//! `Decrypt` operations of a symmetric KMS key, with the context bound as the
//! encryption context, and the credentials of the default credential chain.

use super::{context_digest_hex, DataKey, KeyProvider, WrappedKey, KEY_LEN};
use async_trait::async_trait;
use aws_sdk_kms::error::DisplayErrorContext;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client;
use dragonfly_client_config::dfdaemon::AwsKms as AwsKmsConfig;
use dragonfly_client_core::{Error, Result};
use tracing::info;

/// The key of the encryption context holding the digest of the wrapping
/// context.
const CONTEXT_KEY: &str = "dragonfly:context";

/// AwsKmsKeyProvider wraps the data keys with an AWS KMS key.
pub struct AwsKmsKeyProvider {
    /// The KMS client.
    client: Client,

    /// The id, ARN or alias of the key.
    key_id: String,
}

/// Implements the AWS KMS key provider.
impl AwsKmsKeyProvider {
    /// Creates a new AWS KMS key provider from the configuration and the
    /// default AWS credential chain.
    pub async fn new(config: &AwsKmsConfig) -> Result<Self> {
        let key_id = config.key_id.clone().ok_or_else(|| {
            Error::Encryption("storage.encryption.kms.awsKms.keyId is required".to_string())
        })?;

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &config.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }

        if let Some(endpoint) = &config.endpoint {
            loader = loader.endpoint_url(endpoint);
        }

        let sdk_config = loader.load().await;
        info!(
            "aws kms key provider uses key {} in region {}",
            key_id,
            sdk_config
                .region()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown".to_string())
        );
        Ok(Self::with_client(Client::new(&sdk_config), key_id))
    }

    /// Creates a new AWS KMS key provider with the client.
    pub fn with_client(client: Client, key_id: String) -> Self {
        Self { client, key_id }
    }
}

/// Implements the key provider for the AWS KMS key provider.
#[async_trait]
impl KeyProvider for AwsKmsKeyProvider {
    /// Returns the name of the provider.
    fn name(&self) -> &'static str {
        "awsKms"
    }

    /// Returns the configured key id.
    fn active_key_id(&self) -> &str {
        &self.key_id
    }

    /// Wraps the data key with the key, binding the digest of the context as
    /// the encryption context, and returns the ARN of the key used.
    async fn wrap(&self, data_key: &DataKey, context: &[u8]) -> Result<WrappedKey> {
        let output = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(data_key.to_vec()))
            .encryption_context(CONTEXT_KEY, context_digest_hex(context))
            .send()
            .await
            .map_err(|err| {
                Error::Encryption(format!(
                    "aws kms encrypt failed: {}",
                    DisplayErrorContext(&err)
                ))
            })?;

        let ciphertext = output.ciphertext_blob().ok_or_else(|| {
            Error::Encryption("aws kms encrypt returned no ciphertext".to_string())
        })?;
        Ok(WrappedKey {
            key_id: output.key_id().unwrap_or(&self.key_id).to_string(),
            ciphertext: ciphertext.as_ref().to_vec(),
        })
    }

    /// Unwraps the data key with the configured key, verifying the digest of
    /// the context as the encryption context. The key id of the wrapped key
    /// comes from the untrusted file header and is not used to select the
    /// key, so only ciphertexts of the configured key unwrap.
    async fn unwrap(&self, wrapped_key: &WrappedKey, context: &[u8]) -> Result<DataKey> {
        let output = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(wrapped_key.ciphertext.clone()))
            .encryption_context(CONTEXT_KEY, context_digest_hex(context))
            .send()
            .await
            .map_err(|err| {
                Error::Encryption(format!(
                    "aws kms decrypt with key {} failed: {}",
                    wrapped_key.key_id,
                    DisplayErrorContext(&err)
                ))
            })?;

        let plaintext = output.plaintext().ok_or_else(|| {
            Error::Encryption("aws kms decrypt returned no plaintext".to_string())
        })?;
        if plaintext.as_ref().len() != KEY_LEN {
            return Err(Error::Encryption(
                "aws kms decrypt returned an invalid data encryption key".to_string(),
            ));
        }

        let mut data_key = DataKey::new([0u8; KEY_LEN]);
        data_key.copy_from_slice(plaintext.as_ref());
        Ok(data_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::kms::http::base64_encode;
    use aws_sdk_kms::config::{Credentials, Region};
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEY_ARN: &str =
        "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555";

    fn provider(server: &MockServer) -> AwsKmsKeyProvider {
        let config = aws_sdk_kms::Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .endpoint_url(server.uri())
            .credentials_provider(Credentials::new("AKID", "SECRET", None, None, "test"))
            .build();
        AwsKmsKeyProvider::with_client(Client::from_conf(config), "alias/dragonfly".to_string())
    }

    #[tokio::test]
    async fn test_aws_kms_wrap_unwrap() {
        let server = MockServer::start().await;
        let data_key = DataKey::new([2u8; KEY_LEN]);
        let digest = context_digest_hex(b"context");

        Mock::given(method("POST"))
            .and(header("x-amz-target", "TrentService.Encrypt"))
            .and(body_partial_json(json!({
                "KeyId": "alias/dragonfly",
                "Plaintext": base64_encode(data_key.as_ref()),
                "EncryptionContext": { CONTEXT_KEY: digest },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "CiphertextBlob": base64_encode(b"wrapped"),
                "KeyId": KEY_ARN,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("x-amz-target", "TrentService.Decrypt"))
            .and(body_partial_json(json!({
                "KeyId": "alias/dragonfly",
                "CiphertextBlob": base64_encode(b"wrapped"),
                "EncryptionContext": { CONTEXT_KEY: digest },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Plaintext": base64_encode(data_key.as_ref()),
                "KeyId": KEY_ARN,
            })))
            .mount(&server)
            .await;

        let provider = provider(&server);
        assert_eq!(provider.active_key_id(), "alias/dragonfly");

        let wrapped = provider.wrap(&data_key, b"context").await.unwrap();
        assert_eq!(wrapped.key_id, KEY_ARN);
        assert_eq!(wrapped.ciphertext, b"wrapped");

        let unwrapped = provider.unwrap(&wrapped, b"context").await.unwrap();
        assert_eq!(unwrapped.as_ref(), data_key.as_ref());

        // Another context is a different encryption context, which the mock
        // does not serve, like the service rejecting it.
        assert!(provider.unwrap(&wrapped, b"other").await.is_err());
    }

    #[tokio::test]
    async fn test_aws_kms_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("x-amz-target", "TrentService.Decrypt"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("x-amzn-ErrorType", "InvalidCiphertextException")
                    .set_body_json(
                        json!({ "__type": "InvalidCiphertextException", "message": "" }),
                    ),
            )
            .mount(&server)
            .await;

        let provider = provider(&server);
        let wrapped = WrappedKey {
            key_id: KEY_ARN.to_string(),
            ciphertext: vec![1, 2, 3],
        };
        let err = provider.unwrap(&wrapped, b"context").await.unwrap_err();
        assert!(
            err.to_string().contains("InvalidCiphertextException"),
            "{err}"
        );

        assert!(AwsKmsKeyProvider::new(&AwsKmsConfig::default())
            .await
            .is_err());
    }
}
