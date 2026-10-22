use crate::error::DbError;
use crate::models::{OAuthClientRegistrationRow, OAuthTokenRow};

/// OAuth token data access abstraction for MCP server authentication.
///
/// Provides upsert/get/delete operations keyed by server URL.
/// Token values are stored encrypted; callers handle encryption/decryption.
///
/// Object-safe via `async_trait` to support `Arc<dyn IOAuthTokenRepository>`.
#[async_trait::async_trait]
pub trait IOAuthTokenRepository: Send + Sync {
    /// Gets a token by server URL, or `None` if not found.
    async fn get_by_url(&self, user_id: &str, server_url: &str) -> Result<Option<OAuthTokenRow>, DbError>;

    /// Inserts or updates a token for the given server URL.
    async fn upsert(&self, params: UpsertOAuthTokenParams<'_>) -> Result<OAuthTokenRow, DbError>;

    /// Deletes a token by server URL. Returns `DbError::NotFound` if the URL
    /// doesn't exist.
    async fn delete(&self, user_id: &str, server_url: &str) -> Result<(), DbError>;

    /// Returns the list of server URLs that have stored tokens.
    async fn list_authenticated_urls(&self, user_id: &str) -> Result<Vec<String>, DbError>;

    /// Returns the authorization context (client, token endpoint, scope) the
    /// stored token for `server_url` was issued under, or `None` when there is
    /// no token or the client is unknown.
    ///
    /// Defaults to `None` so repositories without client storage fall back to
    /// discovery and the static client id.
    async fn get_client_registration(
        &self,
        _user_id: &str,
        _server_url: &str,
    ) -> Result<Option<OAuthClientRegistrationRow>, DbError> {
        Ok(None)
    }

    /// Records the authorization context the stored token for `server_url`
    /// was issued under. A no-op when no token row exists.
    async fn set_client_registration(
        &self,
        _user_id: &str,
        _server_url: &str,
        _registration: &OAuthClientRegistrationRow,
    ) -> Result<(), DbError> {
        Ok(())
    }
}

/// Parameters for inserting or updating an OAuth token.
#[derive(Debug)]
pub struct UpsertOAuthTokenParams<'a> {
    pub user_id: &'a str,
    pub server_url: &'a str,
    pub access_token: &'a str,
    pub refresh_token: Option<&'a str>,
    pub token_type: &'a str,
    pub expires_at: Option<aionui_common::TimestampMs>,
}
