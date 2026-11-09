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

//! The helpers shared by the key providers talking to a key management
//! service over HTTPS: the client, the cached bearer tokens, the JSON
//! requests and the encodings.

use base64ct::Encoding;
use dragonfly_client_core::{Error, Result};
use serde_json::Value;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// The timeout of a request to the key management service.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The margin before the expiry of a token at which it is refreshed.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The maximum length of the response body quoted in an error.
const MAX_ERROR_BODY_LEN: usize = 256;

/// Creates the HTTP client of a key provider.
pub(crate) fn new_http_client() -> Result<reqwest::Client> {
    // The reqwest of the workspace is built without a default TLS provider,
    // install the one of the client if none is installed yet.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|err| Error::Encryption(format!("build http client failed: {err}")))
}

/// Token is a bearer token of a key management service.
pub(crate) struct Token {
    /// The value of the token.
    pub value: Zeroizing<String>,

    /// The time the token expires at, `None` for a token that never expires.
    pub expires_at: Option<Instant>,
}

/// Implements the token.
impl Token {
    /// Creates a new token expiring in `expires_in` seconds.
    pub fn new(value: String, expires_in: Option<u64>) -> Self {
        Self {
            value: Zeroizing::new(value),
            expires_at: expires_in.map(|seconds| Instant::now() + Duration::from_secs(seconds)),
        }
    }

    /// Returns whether the token expires soon enough to be refreshed.
    fn is_expiring(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= Instant::now() + TOKEN_REFRESH_MARGIN)
    }
}

/// TokenCache caches the bearer token of a key management service and
/// refreshes it before it expires.
#[derive(Default)]
pub(crate) struct TokenCache {
    /// The cached token.
    token: Mutex<Option<Token>>,
}

/// Implements the token cache.
impl TokenCache {
    /// Returns the cached token, refreshing it with `refresh` when it is
    /// missing or expiring. The refreshes are serialized.
    pub async fn get<F, Fut>(&self, refresh: F) -> Result<Zeroizing<String>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Token>>,
    {
        let mut guard = self.token.lock().await;
        if let Some(token) = guard.as_ref() {
            if !token.is_expiring() {
                return Ok(token.value.clone());
            }
        }

        let token = refresh().await?;
        let value = token.value.clone();
        *guard = Some(token);
        Ok(value)
    }

    /// Forgets the cached token, e.g. after the service rejected it.
    pub async fn invalidate(&self) {
        *self.token.lock().await = None;
    }
}

/// HttpError is the error of a request to a key management service.
#[derive(Debug)]
pub(crate) enum HttpError {
    /// The service answered with a non-success status.
    Status(u16, String),

    /// The request failed before a response or the response is invalid.
    Other(String),
}

/// Implements the display of the HTTP error.
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Status(status, body) => write!(f, "status {status}: {body}"),
            HttpError::Other(message) => write!(f, "{message}"),
        }
    }
}

/// Implements the HTTP error.
impl HttpError {
    /// Returns whether the service rejected the credentials, so a refreshed
    /// token may succeed.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, HttpError::Status(401 | 403, _))
    }

    /// Converts the error into the encryption error of the operation.
    pub fn into_error(self, what: &str) -> Error {
        Error::Encryption(format!("{what} failed: {self}"))
    }
}

/// Sends the request and parses the JSON response, failing on a non-success
/// status.
pub(crate) async fn send_json(
    request: reqwest::RequestBuilder,
) -> std::result::Result<Value, HttpError> {
    let response = request
        .send()
        .await
        .map_err(|err| HttpError::Other(format!("request failed: {err}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|err| HttpError::Other(format!("read response failed: {err}")))?;

    if !status.is_success() {
        return Err(HttpError::Status(status.as_u16(), snippet(&body)));
    }

    serde_json::from_slice(&body)
        .map_err(|err| HttpError::Other(format!("invalid json response: {err}")))
}

/// Sets the JSON body of the request. The reqwest of the workspace is built
/// without its json feature.
pub(crate) fn json_body(request: reqwest::RequestBuilder, body: &Value) -> reqwest::RequestBuilder {
    request
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
}

/// Returns the start of the response body for an error message.
fn snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut snippet: String = text.chars().take(MAX_ERROR_BODY_LEN).collect();
    if snippet.len() < text.len() {
        snippet.push_str("...");
    }

    snippet
}

/// Returns the string field of the JSON value.
pub(crate) fn str_field<'a>(value: &'a Value, field: &str, what: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Encryption(format!("{what} response has no {field}")))
}

/// Returns the integer field of the JSON value, which may be encoded as a
/// string by some services.
pub(crate) fn u64_field(value: &Value, field: &str) -> Option<u64> {
    match value.get(field) {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(string)) => string.parse().ok(),
        _ => None,
    }
}

/// Encodes the bytes as standard base64.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    base64ct::Base64::encode_string(data)
}

/// Decodes the standard base64 string.
pub(crate) fn base64_decode(data: &str, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    base64ct::Base64::decode_vec(data.trim())
        .map(Zeroizing::new)
        .map_err(|err| Error::Encryption(format!("{what} is not valid base64: {err}")))
}

/// Encodes the bytes as unpadded URL-safe base64.
pub(crate) fn base64url_encode(data: &[u8]) -> String {
    base64ct::Base64UrlUnpadded::encode_string(data)
}

/// Decodes the URL-safe base64 string, padded or not.
pub(crate) fn base64url_decode(data: &str, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    let trimmed = data.trim().trim_end_matches('=');
    base64ct::Base64UrlUnpadded::decode_vec(trimmed)
        .map(Zeroizing::new)
        .map_err(|err| Error::Encryption(format!("{what} is not valid base64url: {err}")))
}

/// Returns the non-empty value of the environment variable.
pub(crate) fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Reads a secret, e.g. a token, from the file, trimming the whitespace.
pub(crate) async fn read_secret_file(path: &Path) -> Result<Zeroizing<String>> {
    let content =
        Zeroizing::new(tokio::fs::read_to_string(path).await.map_err(|err| {
            Error::Encryption(format!("read secret file {path:?} failed: {err}"))
        })?);
    Ok(Zeroizing::new(content.trim().to_string()))
}

/// Returns the current unix time in seconds.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_token_cache_refreshes_expiring_tokens() {
        let cache = TokenCache::default();
        let refreshes = AtomicUsize::new(0);
        let refresh = |expires_in: Option<u64>| {
            refreshes.fetch_add(1, Ordering::SeqCst);
            async move { Ok(Token::new("token".to_string(), expires_in)) }
        };

        // A token without expiry is refreshed once.
        assert_eq!(cache.get(|| refresh(None)).await.unwrap().as_str(), "token");
        assert_eq!(cache.get(|| refresh(None)).await.unwrap().as_str(), "token");
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);

        // A token inside the refresh margin is refreshed, a long-lived one is
        // not.
        cache.invalidate().await;
        cache.get(|| refresh(Some(10))).await.unwrap();
        cache.get(|| refresh(Some(3600))).await.unwrap();
        cache.get(|| refresh(Some(3600))).await.unwrap();
        assert_eq!(refreshes.load(Ordering::SeqCst), 3);

        // A failed refresh keeps nothing cached.
        cache.invalidate().await;
        let result = cache
            .get(|| async { Err::<Token, Error>(Error::Encryption("down".to_string())) })
            .await;
        assert!(result.is_err());
        cache.get(|| refresh(None)).await.unwrap();
        assert_eq!(refreshes.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_encodings() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(
            base64_decode("aGVsbG8=\n", "value").unwrap().as_slice(),
            b"hello"
        );
        assert!(base64_decode("not base64!", "value").is_err());

        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(
            base64url_decode("-_8", "value").unwrap().as_slice(),
            &[0xfb, 0xff]
        );
        assert_eq!(
            base64url_decode("-_8=", "value").unwrap().as_slice(),
            &[0xfb, 0xff]
        );

        let value: Value = serde_json::from_str(r#"{"a": "1", "b": 2, "c": "x"}"#).unwrap();
        assert_eq!(u64_field(&value, "a"), Some(1));
        assert_eq!(u64_field(&value, "b"), Some(2));
        assert_eq!(u64_field(&value, "c"), None);
        assert_eq!(str_field(&value, "c", "test").unwrap(), "x");
        assert!(str_field(&value, "b", "test").is_err());
    }

    #[test]
    fn test_http_error() {
        assert!(HttpError::Status(401, String::new()).is_unauthorized());
        assert!(HttpError::Status(403, String::new()).is_unauthorized());
        assert!(!HttpError::Status(500, String::new()).is_unauthorized());
        assert!(!HttpError::Other(String::new()).is_unauthorized());
        assert_eq!(
            HttpError::Status(500, "boom".to_string())
                .into_error("encrypt")
                .to_string(),
            "encryption: encrypt failed: status 500: boom"
        );
        assert_eq!(snippet(&[b'a'; 300]).len(), MAX_ERROR_BODY_LEN + 3);
    }
}
