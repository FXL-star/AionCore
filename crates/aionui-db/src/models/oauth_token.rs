use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for the `oauth_tokens` table.
///
/// Stores OAuth tokens keyed by MCP server URL.
/// Token values (`access_token`, `refresh_token`) should be stored
/// encrypted; callers handle encryption/decryption.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OAuthTokenRow {
    pub user_id: String,
    /// MCP server URL (primary key).
    pub server_url: String,
    /// Encrypted OAuth access token.
    pub access_token: String,
    /// Encrypted OAuth refresh token (optional).
    pub refresh_token: Option<String>,
    /// Token type, typically "bearer".
    pub token_type: String,
    /// Token expiration timestamp (milliseconds).
    pub expires_at: Option<TimestampMs>,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}

/// Authorization context a stored token was issued under (the
/// `oauth_tokens.client_*`, `token_endpoint` and `scope` columns).
///
/// Refreshing must present the same client as the login that obtained the
/// refresh token; dynamically registered clients differ per server and per
/// registration. `client_secret` is stored encrypted, like the tokens.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OAuthClientRegistrationRow {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// RFC 7591 `token_endpoint_auth_method`, when the server reported one.
    #[sqlx(rename = "client_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: Option<String>,
    pub token_endpoint: Option<String>,
    pub scope: Option<String>,
}
