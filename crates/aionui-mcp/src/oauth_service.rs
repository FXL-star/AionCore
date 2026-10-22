use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aionui_api_types::{OAuthLoginResponse, OAuthStatusResponse};
use aionui_common::{TimestampMs, decrypt_string, encrypt_string, now_ms};
use aionui_db::models::OAuthClientRegistrationRow;
use aionui_db::{IOAuthTokenRepository, UpsertOAuthTokenParams};
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::McpError;
use crate::oauth_discovery::{ClientCredentials, OAuthDiscovery, OAuthServerMetadata};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timeout for the OAuth callback server waiting for the redirect.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);

/// Path of the loopback redirect URI; requests to any other path are ignored.
const CALLBACK_PATH: &str = "/callback";

/// Largest callback request we read; the redirect is a single GET line.
const CALLBACK_MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Static client ID, used only when the authorization server offers neither a
/// client ID metadata document nor dynamic client registration (the spec's
/// "pre-registered client" case for servers that provisioned `aionui`).
const DEFAULT_CLIENT_ID: &str = "aionui";

/// Env var naming this client's OAuth Client ID Metadata Document (an HTTPS
/// URL with a path). When set and the authorization server advertises
/// `client_id_metadata_document_supported`, the URL is used as `client_id`.
pub const CLIENT_METADATA_URL_ENV: &str = "AIONUI_MCP_OAUTH_CLIENT_METADATA_URL";

/// Token expiry safety margin (refresh 5 minutes before expiration).
const EXPIRY_MARGIN_MS: i64 = 5 * 60 * 1000;

/// Upper bound for one token lookup (including a refresh round-trip) while
/// assembling a request. A slow auth server must not block session start.
const AUTHORIZATION_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Marker for values encrypted at rest. Rows written before encryption hold
/// plaintext and are read as-is, then re-sealed on the next write.
const SEALED_PREFIX: &str = "enc:v1:";

// ---------------------------------------------------------------------------
// Pending login state
// ---------------------------------------------------------------------------

/// State held while waiting for the OAuth callback redirect.
///
/// Stores endpoint URLs rather than the typed `BasicClient` to avoid
/// complex generic type parameters from the `oauth2` crate.
///
/// Keyed by `(user_id, state)`; the callback must echo that `state`.
struct PendingLogin {
    pkce_verifier: PkceCodeVerifier,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    /// RFC 8707 resource indicator (canonical MCP server URI). The MCP spec
    /// requires it in both the authorization and the token request, so the
    /// exchange reuses exactly the value the browser saw.
    resource: Option<String>,
    /// Credentials the authorize request was made with. The token exchange must
    /// reuse exactly these — a dynamically registered client_id differs per
    /// server and per registration.
    credentials: ClientCredentials,
    /// Scope requested on the authorization request (spec scope selection).
    scope: Option<String>,
}

/// An authorization request ready to be opened in the browser.
struct LoginFlow {
    authorize_url: String,
    listener: TcpListener,
    /// `state` sent on the authorization request; the callback must echo it.
    state: String,
}

/// `(user_id, server_url)` a refresh lock guards.
type RefreshKey = (String, String);

/// A stored token, decrypted.
struct StoredToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<TimestampMs>,
}

impl StoredToken {
    fn is_expired(&self, margin_ms: i64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now_ms() >= expires_at - margin_ms)
    }
}

// ---------------------------------------------------------------------------
// McpOAuthService
// ---------------------------------------------------------------------------

/// Client side of the MCP authorization spec (OAuth 2.1 + PKCE).
///
/// Manages the full lifecycle: discovery → client registration → authorize →
/// callback → token exchange → storage → refresh → logout. Discovery details
/// live in [`crate::oauth_discovery`].
#[derive(Clone)]
pub struct McpOAuthService {
    token_repo: Arc<dyn IOAuthTokenRepository>,
    http_client: reqwest::Client,
    /// Mutex protecting pending login state by (user_id, oauth_state).
    pending: Arc<Mutex<HashMap<(String, String), PendingLogin>>>,
    /// One lock per (user_id, server_url) so concurrent requests never refresh
    /// the same token twice: authorization servers rotate refresh tokens for
    /// public clients (OAuth 2.1 §4.3.1), so a second refresh with the old
    /// refresh token fails and may revoke the whole grant.
    refresh_locks: Arc<Mutex<HashMap<RefreshKey, Arc<Mutex<()>>>>>,
    /// AES-256-GCM key for tokens and client secrets at rest. `None` stores
    /// plaintext (tests and callers without a key).
    encryption_key: Option<[u8; 32]>,
    /// Client ID Metadata Document URL, when this deployment hosts one.
    client_metadata_url: Option<String>,
}

impl McpOAuthService {
    pub fn new(token_repo: Arc<dyn IOAuthTokenRepository>, http_client: reqwest::Client) -> Self {
        let client_metadata_url = std::env::var(CLIENT_METADATA_URL_ENV)
            .ok()
            .filter(|url| is_valid_client_metadata_url(url));
        Self {
            token_repo,
            http_client,
            pending: Arc::new(Mutex::new(HashMap::new())),
            refresh_locks: Arc::new(Mutex::new(HashMap::new())),
            encryption_key: None,
            client_metadata_url,
        }
    }

    /// Encrypt tokens and client secrets at rest with `key` (the MCP spec
    /// requires secure token storage).
    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Use `url` as this client's Client ID Metadata Document when the
    /// authorization server supports it. Invalid URLs are ignored.
    pub fn with_client_metadata_url(mut self, url: impl Into<String>) -> Self {
        let url = url.into();
        self.client_metadata_url = is_valid_client_metadata_url(&url).then_some(url);
        self
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Check whether the given server URL has a usable OAuth token, refreshing
    /// an expired one when a refresh token is available.
    pub async fn check_oauth_status(&self, user_id: &str, server_url: &str) -> Result<OAuthStatusResponse, McpError> {
        let authenticated = self.has_valid_token(user_id, server_url).await?;
        Ok(OAuthStatusResponse { authenticated })
    }

    /// Start the OAuth PKCE login flow for the given MCP server URL.
    ///
    /// 1. Discover the authorization server (WWW-Authenticate challenge,
    ///    RFC 9728, RFC 8414 / OIDC) and verify PKCE S256 support
    /// 2. Resolve the client (metadata document, DCR, or static ID)
    /// 3. Start a loopback callback server on a random port
    /// 4. Open the authorization URL (PKCE, `state`, `resource`, `scope`)
    /// 5. Wait for the redirect carrying the matching `state`
    /// 6. Exchange the code for tokens and persist them
    pub async fn login(&self, user_id: &str, server_url: &str) -> Result<OAuthLoginResponse, McpError> {
        let flow = self.prepare_login_flow(user_id, server_url).await?;

        // Open browser.
        debug!(url = %flow.authorize_url, "Opening browser for OAuth authorization");
        if let Err(e) = open::that(&flow.authorize_url) {
            warn!("Failed to open browser: {e}");
        }

        // Wait for callback.
        let code = match wait_for_callback(flow.listener, &flow.state).await {
            Ok(code) => code,
            Err(e) => {
                self.clear_pending_for_user(user_id).await;
                return Ok(OAuthLoginResponse {
                    success: false,
                    error: Some(e.to_string()),
                });
            }
        };

        // Exchange code for tokens.
        match self.exchange_code(user_id, server_url, code, flow.state).await {
            Ok(()) => Ok(OAuthLoginResponse {
                success: true,
                error: None,
            }),
            Err(e) => {
                self.clear_pending_for_user(user_id).await;
                Ok(OAuthLoginResponse {
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Logout from the given MCP server URL (delete stored token and the
    /// client registration stored with it).
    ///
    /// Idempotent: returns Ok even if no token was stored.
    pub async fn logout(&self, user_id: &str, server_url: &str) -> Result<(), McpError> {
        match self.token_repo.delete(user_id, server_url).await {
            Ok(()) => {
                debug!(server_url, "OAuth token deleted");
                Ok(())
            }
            Err(aionui_db::DbError::NotFound(_)) => {
                debug!(server_url, "No OAuth token to delete (idempotent)");
                Ok(())
            }
            Err(e) => Err(McpError::Database(e)),
        }
    }

    /// Return the list of server URLs that have stored OAuth tokens.
    pub async fn get_authenticated_servers(&self, user_id: &str) -> Result<Vec<String>, McpError> {
        let urls = self.token_repo.list_authenticated_urls(user_id).await?;
        Ok(urls)
    }

    /// Get a valid access token for the given server URL.
    ///
    /// If the stored token is expired (or about to) and a refresh token is
    /// available, refreshes before returning. A failed refresh returns the
    /// stored token so the server reports the error. Returns `None` if no
    /// token is stored for this URL.
    pub async fn get_token(&self, user_id: &str, server_url: &str) -> Result<Option<String>, McpError> {
        let Some(token) = self.load_token(user_id, server_url).await? else {
            return Ok(None);
        };

        if !token.is_expired(EXPIRY_MARGIN_MS) || token.refresh_token.is_none() {
            return Ok(Some(token.access_token));
        }

        match self.refresh_serialized(user_id, server_url, &token.access_token).await {
            Ok(new_token) => Ok(Some(new_token)),
            Err(e) => {
                warn!(
                    server_url,
                    error = %e,
                    "Token refresh failed, returning expired token"
                );
                Ok(Some(token.access_token))
            }
        }
    }

    /// Add `Authorization: Bearer <token>` for `server_url` when a token is stored.
    ///
    /// Tokens are keyed by the exact server URL they were issued for, so a
    /// token is only ever sent to the MCP server whose authorization server
    /// issued it (no cross-server token reuse).
    ///
    /// Best effort: an existing `Authorization` header (any casing) always wins,
    /// and DB errors/timeouts are logged and ignored — a session must still start.
    /// Never logs the token or the resulting header value.
    pub async fn apply_authorization(&self, user_id: &str, server_url: &str, headers: &mut HashMap<String, String>) {
        if headers.keys().any(|key| key.eq_ignore_ascii_case("authorization")) {
            return;
        }
        match tokio::time::timeout(AUTHORIZATION_LOOKUP_TIMEOUT, self.get_token(user_id, server_url)).await {
            Ok(Ok(Some(token))) => {
                debug!(server_url, "Attached stored OAuth token to MCP request headers");
                headers.insert("Authorization".to_owned(), format!("Bearer {token}"));
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                warn!(server_url, error = %error, "OAuth token lookup failed; continuing without Authorization")
            }
            Err(_) => warn!(
                server_url,
                timeout_secs = AUTHORIZATION_LOOKUP_TIMEOUT.as_secs(),
                "OAuth token lookup timed out; continuing without Authorization"
            ),
        }
    }

    /// Force a token refresh for `server_url`, bypassing the local expiry check.
    ///
    /// [`Self::get_token`] only refreshes once the stored expiry is near, which
    /// is not enough when a server rejects a request with HTTP 401: the token
    /// may be revoked, or the local clock may disagree with the server's. The
    /// caller retries at most once with the returned token.
    ///
    /// Returns `None` when no token is stored for this server.
    pub async fn refresh_now(&self, user_id: &str, server_url: &str) -> Result<Option<String>, McpError> {
        let Some(token) = self.load_token(user_id, server_url).await? else {
            return Ok(None);
        };

        if token.refresh_token.is_none() {
            // No refresh token: nothing better to offer than what we have.
            return Ok(Some(token.access_token));
        }

        match self.refresh_serialized(user_id, server_url, &token.access_token).await {
            Ok(token) => Ok(Some(token)),
            Err(error) => {
                warn!(server_url, error = %error, "Forced token refresh failed after HTTP 401");
                Err(error)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Discover the authorization server, resolve the client, generate PKCE,
    /// bind the callback server, and store the pending state.
    async fn prepare_login_flow(&self, user_id: &str, server_url: &str) -> Result<LoginFlow, McpError> {
        let discovery = OAuthDiscovery::new(&self.http_client);
        // Step-up authorization: when a token exists, a server needing more
        // scope answers `403 insufficient_scope` with the scope set to request,
        // which is authoritative over the unauthenticated challenge.
        let step_up = match self.load_token(user_id, server_url).await {
            Ok(Some(token)) => discovery.probe_step_up_challenge(server_url, &token.access_token).await,
            _ => None,
        };
        let challenge = match step_up {
            Some(challenge) => {
                debug!(server_url, "Re-authorizing for insufficient_scope (step-up)");
                Some(challenge)
            }
            None => discovery.probe_challenge(server_url).await,
        };
        let discovered = discovery.discover_with_challenge(server_url, challenge).await?;
        let metadata = discovered.metadata;
        let scope = discovered.scope;

        let auth_url = AuthUrl::new(metadata.authorization_endpoint.clone())
            .map_err(|e| McpError::OAuth(format!("Invalid auth URL: {e}")))?;
        let token_url = TokenUrl::new(metadata.token_endpoint.clone())
            .map_err(|e| McpError::OAuth(format!("Invalid token URL: {e}")))?;

        // Loopback redirect (RFC 8252 §7.3): the spec allows `localhost` or
        // HTTPS redirect URIs, and a random port avoids collisions.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| McpError::OAuth(format!("Failed to bind callback server: {e}")))?;
        let callback_port = listener
            .local_addr()
            .map_err(|e| McpError::OAuth(format!("Failed to get callback port: {e}")))?
            .port();

        let redirect_url_str = format!("http://127.0.0.1:{callback_port}{CALLBACK_PATH}");
        let redirect = RedirectUrl::new(redirect_url_str.clone())
            .map_err(|e| McpError::OAuth(format!("Invalid redirect URL: {e}")))?;

        let credentials = self
            .resolve_client_credentials(server_url, &metadata, &redirect_url_str, scope.as_deref())
            .await?;

        let client = configure_client_auth(
            BasicClient::new(ClientId::new(credentials.client_id.clone()))
                .set_auth_uri(auth_url)
                .set_token_uri(token_url)
                .set_redirect_uri(redirect),
            &credentials,
        );

        // Discovery verified S256 support; PKCE is mandatory (OAuth 2.1).
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // RFC 8707: bind the requested token to this MCP server by sending
        // `resource` on the authorization request.
        let resource = Self::resource_indicator(server_url);
        let mut authorize_request = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);
        if let Some(resource) = resource.as_deref() {
            authorize_request = authorize_request.add_extra_param("resource", resource);
        }
        if let Some(scope) = scope.as_deref() {
            authorize_request =
                authorize_request.add_scopes(scope.split_whitespace().map(|s| Scope::new(s.to_owned())));
        }
        let (authorize_url, csrf_token) = authorize_request.url();
        let state = csrf_token.secret().clone();

        {
            let mut pending = self.pending.lock().await;
            pending.insert(
                (user_id.to_string(), state.clone()),
                PendingLogin {
                    pkce_verifier,
                    auth_url: metadata.authorization_endpoint,
                    token_url: metadata.token_endpoint,
                    redirect_url: redirect_url_str,
                    resource,
                    credentials,
                    scope,
                },
            );
        }

        Ok(LoginFlow {
            authorize_url: authorize_url.to_string(),
            listener,
            state,
        })
    }

    /// Whether a usable token exists, refreshing an expired one if possible.
    async fn has_valid_token(&self, user_id: &str, server_url: &str) -> Result<bool, McpError> {
        let Some(token) = self.load_token(user_id, server_url).await? else {
            return Ok(false);
        };

        if !token.is_expired(0) {
            return Ok(true);
        }
        if token.refresh_token.is_none() {
            return Ok(false);
        }
        match self.refresh_serialized(user_id, server_url, &token.access_token).await {
            Ok(_) => Ok(true),
            Err(error) => {
                debug!(server_url, error = %error, "Expired OAuth token could not be refreshed");
                Ok(false)
            }
        }
    }

    /// Resolve the OAuth client for a login, in the spec's priority order:
    ///
    /// 1. Client ID Metadata Document, when the authorization server advertises
    ///    `client_id_metadata_document_supported` and this deployment hosts one
    /// 2. RFC 7591 dynamic client registration, when advertised
    /// 3. The static client ID, for servers that pre-provisioned it
    ///
    /// DCR registers a fresh client per login: the loopback redirect URI uses
    /// a new port every time, and authorization servers match redirect URIs
    /// exactly. The registration is persisted with the token for refreshes.
    async fn resolve_client_credentials(
        &self,
        server_url: &str,
        metadata: &OAuthServerMetadata,
        redirect_uri: &str,
        scope: Option<&str>,
    ) -> Result<ClientCredentials, McpError> {
        if metadata.client_id_metadata_document_supported == Some(true)
            && let Some(url) = self.client_metadata_url.as_deref()
        {
            debug!(server_url, "Using client ID metadata document as client_id");
            return Ok(ClientCredentials {
                client_id: url.to_owned(),
                client_secret: None,
                token_endpoint_auth_method: Some("none".to_owned()),
            });
        }

        if let Some(registration_endpoint) = metadata.registration_endpoint.as_deref() {
            let credentials = OAuthDiscovery::new(&self.http_client)
                .register_client(registration_endpoint, redirect_uri, scope)
                .await?;
            debug!(server_url, "Registered OAuth client via dynamic client registration");
            return Ok(credentials);
        }

        warn!(
            server_url,
            client_id = DEFAULT_CLIENT_ID,
            "Authorization server supports neither client ID metadata documents nor dynamic client \
             registration; using the static client ID"
        );
        Ok(ClientCredentials {
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_secret: None,
            token_endpoint_auth_method: None,
        })
    }

    /// Load and decrypt the stored token for `server_url`.
    async fn load_token(&self, user_id: &str, server_url: &str) -> Result<Option<StoredToken>, McpError> {
        let Some(row) = self.token_repo.get_by_url(user_id, server_url).await? else {
            return Ok(None);
        };
        Ok(Some(StoredToken {
            access_token: self.open(&row.access_token)?,
            refresh_token: row.refresh_token.as_deref().map(|token| self.open(token)).transpose()?,
            expires_at: row.expires_at,
        }))
    }

    /// Load and decrypt the authorization context stored with the token.
    async fn load_registration(&self, user_id: &str, server_url: &str) -> Option<OAuthClientRegistrationRow> {
        match self.token_repo.get_client_registration(user_id, server_url).await {
            Ok(Some(mut registration)) => {
                match registration
                    .client_secret
                    .as_deref()
                    .map(|secret| self.open(secret))
                    .transpose()
                {
                    Ok(secret) => registration.client_secret = secret,
                    Err(error) => {
                        warn!(server_url, error = %error, "Stored OAuth client secret is unreadable; ignoring the registration");
                        return None;
                    }
                }
                Some(registration)
            }
            Ok(None) => None,
            Err(error) => {
                warn!(server_url, error = %error, "Failed to load stored OAuth client registration");
                None
            }
        }
    }

    /// Get or create the refresh lock for one (user, server) pair.
    async fn refresh_lock(&self, user_id: &str, server_url: &str) -> Arc<Mutex<()>> {
        let mut locks = self.refresh_locks.lock().await;
        Arc::clone(
            locks
                .entry((user_id.to_owned(), server_url.to_owned()))
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Refresh the token for `server_url`, at most once per stale token.
    ///
    /// `seen_access_token` is the token the caller found stale. If another
    /// task refreshed it while this one waited for the lock, the newer token
    /// is returned without a second refresh — with rotating refresh tokens,
    /// that second refresh would present an already-used refresh token.
    async fn refresh_serialized(
        &self,
        user_id: &str,
        server_url: &str,
        seen_access_token: &str,
    ) -> Result<String, McpError> {
        let lock = self.refresh_lock(user_id, server_url).await;
        let _guard = lock.lock().await;

        let current = self
            .load_token(user_id, server_url)
            .await?
            .ok_or_else(|| McpError::OAuth("OAuth token was removed during refresh".to_string()))?;
        if current.access_token != seen_access_token {
            return Ok(current.access_token);
        }
        let refresh_token = current
            .refresh_token
            .ok_or_else(|| McpError::OAuth("No refresh token stored; sign in again".to_string()))?;

        self.refresh_token(user_id, server_url, &refresh_token).await
    }

    /// Exchange `refresh_token_value` for a new access token and persist it.
    ///
    /// Uses the client and token endpoint stored with the token; rows written
    /// before that was recorded fall back to discovery and the static client.
    async fn refresh_token(
        &self,
        user_id: &str,
        server_url: &str,
        refresh_token_value: &str,
    ) -> Result<String, McpError> {
        let registration = self.load_registration(user_id, server_url).await;

        let token_endpoint = match registration.as_ref().and_then(|r| r.token_endpoint.clone()) {
            Some(endpoint) => endpoint,
            None => {
                OAuthDiscovery::new(&self.http_client)
                    .discover(server_url)
                    .await?
                    .metadata
                    .token_endpoint
            }
        };
        let token_url =
            TokenUrl::new(token_endpoint).map_err(|e| McpError::OAuth(format!("Invalid token URL: {e}")))?;

        let credentials = registration
            .map(|r| ClientCredentials {
                client_id: r.client_id,
                client_secret: r.client_secret,
                token_endpoint_auth_method: r.token_endpoint_auth_method,
            })
            .unwrap_or_else(|| ClientCredentials {
                client_id: DEFAULT_CLIENT_ID.to_string(),
                client_secret: None,
                token_endpoint_auth_method: None,
            });
        let client = configure_client_auth(
            BasicClient::new(ClientId::new(credentials.client_id.clone())).set_token_uri(token_url),
            &credentials,
        );

        let http_client = Self::build_no_redirect_client()?;

        let refresh_token = RefreshToken::new(refresh_token_value.to_string());
        let mut token_request = client.exchange_refresh_token(&refresh_token);
        if let Some(resource) = Self::resource_indicator(server_url) {
            // A refresh is an access-token request too: keep the RFC 8707
            // resource indicator so the new token stays audience-bound.
            token_request = token_request.add_extra_param("resource", resource);
        }
        let token_result = token_request
            .request_async(&http_client)
            .await
            .map_err(|e| McpError::OAuth(format!("Token refresh failed: {e}")))?;
        ensure_bearer(token_result.token_type())?;

        let new_access_token = token_result.access_token().secret().clone();
        let expires_at: Option<TimestampMs> = token_result.expires_in().map(|d| now_ms() + d.as_millis() as i64);

        // Refresh tokens rotate for public clients: prefer the new one, and
        // keep the old one only when the server did not issue a replacement.
        let new_refresh = token_result
            .refresh_token()
            .map(|t| t.secret().as_str())
            .unwrap_or(refresh_token_value);

        let sealed_access = self.seal(&new_access_token)?;
        let sealed_refresh = self.seal(new_refresh)?;
        self.token_repo
            .upsert(UpsertOAuthTokenParams {
                user_id,
                server_url,
                access_token: &sealed_access,
                refresh_token: Some(&sealed_refresh),
                token_type: "bearer",
                expires_at,
            })
            .await?;

        debug!(server_url, "OAuth token refreshed successfully");
        Ok(new_access_token)
    }

    /// Build the RFC 8707 resource indicator for an MCP server URL.
    ///
    /// The MCP spec requires the `resource` parameter on both the
    /// authorization and token requests. Its value is an absolute URI with no
    /// fragment (RFC 8707 §2) and no query (the RFC 9728 resource-identifier
    /// form); `Url` normalizes scheme/host case, and a bare origin drops its
    /// trailing slash per the MCP canonical-URI guidance. Returns `None` when
    /// `server_url` is not an absolute http(s) URL.
    fn resource_indicator(server_url: &str) -> Option<String> {
        let mut url = url::Url::parse(server_url).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        url.set_fragment(None);
        url.set_query(None);
        let mut resource = url.to_string();
        if url.path() == "/" {
            resource.pop();
        }
        Some(resource)
    }

    /// Build a no-redirect reqwest client for OAuth token exchange.
    fn build_no_redirect_client() -> Result<reqwest::Client, McpError> {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| McpError::OAuth(format!("Failed to build HTTP client: {e}")))
    }

    /// Exchange the authorization code for tokens and persist them, together
    /// with the client and token endpoint needed to refresh them later.
    async fn exchange_code(
        &self,
        user_id: &str,
        server_url: &str,
        code: String,
        state: String,
    ) -> Result<(), McpError> {
        let pending = {
            let mut guard = self.pending.lock().await;
            guard
                .remove(&(user_id.to_string(), state))
                .ok_or_else(|| McpError::OAuth("No pending login state".to_string()))?
        };

        let auth_url = AuthUrl::new(pending.auth_url).map_err(|e| McpError::OAuth(format!("Invalid auth URL: {e}")))?;
        let token_url =
            TokenUrl::new(pending.token_url.clone()).map_err(|e| McpError::OAuth(format!("Invalid token URL: {e}")))?;
        let redirect = RedirectUrl::new(pending.redirect_url)
            .map_err(|e| McpError::OAuth(format!("Invalid redirect URL: {e}")))?;

        let credentials = pending.credentials;
        let client = configure_client_auth(
            BasicClient::new(ClientId::new(credentials.client_id.clone()))
                .set_auth_uri(auth_url)
                .set_token_uri(token_url)
                .set_redirect_uri(redirect),
            &credentials,
        );

        let http_client = Self::build_no_redirect_client()?;

        let mut token_request = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pending.pkce_verifier);
        if let Some(resource) = pending.resource.as_deref() {
            // Must match the authorization request (RFC 8707), otherwise the
            // issued token is not audience-bound to this MCP server.
            token_request = token_request.add_extra_param("resource", resource);
        }
        let token_result = token_request
            .request_async(&http_client)
            .await
            .map_err(|e| McpError::OAuth(format!("Token exchange failed: {e}")))?;
        ensure_bearer(token_result.token_type())?;

        self.persist_token(user_id, server_url, &token_result).await?;

        // The refresh token is bound to this client. Persist it next to the
        // token so refreshing after a restart does not fall back to the static
        // client id (which the server rejects with `invalid_client`).
        let granted_scope = token_result
            .scopes()
            .map(|scopes| scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
            .or(pending.scope);
        let registration = OAuthClientRegistrationRow {
            client_id: credentials.client_id,
            client_secret: credentials.client_secret.as_deref().map(|s| self.seal(s)).transpose()?,
            token_endpoint_auth_method: credentials.token_endpoint_auth_method,
            token_endpoint: Some(pending.token_url),
            scope: granted_scope,
        };
        self.token_repo
            .set_client_registration(user_id, server_url, &registration)
            .await?;
        debug!(server_url, "OAuth tokens stored successfully");
        Ok(())
    }

    /// Persist a token response to the DB, encrypted at rest.
    async fn persist_token<TR: TokenResponse>(
        &self,
        user_id: &str,
        server_url: &str,
        token_result: &TR,
    ) -> Result<(), McpError> {
        let expires_at: Option<TimestampMs> = token_result.expires_in().map(|d| now_ms() + d.as_millis() as i64);
        let access_token = self.seal(token_result.access_token().secret())?;
        let refresh_token = token_result
            .refresh_token()
            .map(|t| self.seal(t.secret()))
            .transpose()?;

        self.token_repo
            .upsert(UpsertOAuthTokenParams {
                user_id,
                server_url,
                access_token: &access_token,
                refresh_token: refresh_token.as_deref(),
                token_type: "bearer",
                expires_at,
            })
            .await?;

        Ok(())
    }

    /// Encrypt a secret for storage (no-op without a key).
    fn seal(&self, plaintext: &str) -> Result<String, McpError> {
        let Some(key) = self.encryption_key.as_ref() else {
            return Ok(plaintext.to_owned());
        };
        let ciphertext = encrypt_string(plaintext, key)
            .map_err(|e| McpError::OAuth(format!("Failed to encrypt OAuth credential: {e}")))?;
        Ok(format!("{SEALED_PREFIX}{ciphertext}"))
    }

    /// Decrypt a stored secret. Values without the sealed prefix are legacy
    /// plaintext and returned as-is.
    fn open(&self, stored: &str) -> Result<String, McpError> {
        let Some(ciphertext) = stored.strip_prefix(SEALED_PREFIX) else {
            return Ok(stored.to_owned());
        };
        let key = self.encryption_key.as_ref().ok_or_else(|| {
            McpError::OAuth("OAuth credential is encrypted but no encryption key is configured".to_string())
        })?;
        decrypt_string(ciphertext, key).map_err(|e| {
            McpError::OAuth(format!(
                "Failed to decrypt stored OAuth credential ({e}); sign in again"
            ))
        })
    }

    /// Clear the pending login state.
    async fn clear_pending_for_user(&self, user_id: &str) {
        let mut guard = self.pending.lock().await;
        guard.retain(|(pending_user_id, _), _| pending_user_id != user_id);
    }
}

/// Configure how the client authenticates at the token endpoint, from its
/// RFC 7591 `token_endpoint_auth_method`.
///
/// Public clients (`none`, or no secret) send only `client_id` in the body.
/// `client_secret_post` sends the secret in the body; everything else with a
/// secret uses HTTP Basic, the RFC 7591 default.
fn configure_client_auth<
    HasAuthUrl: oauth2::EndpointState,
    HasDeviceAuthUrl: oauth2::EndpointState,
    HasIntrospectionUrl: oauth2::EndpointState,
    HasRevocationUrl: oauth2::EndpointState,
    HasTokenUrl: oauth2::EndpointState,
>(
    client: BasicClient<HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl, HasTokenUrl>,
    credentials: &ClientCredentials,
) -> BasicClient<HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl, HasTokenUrl> {
    let Some(secret) = credentials.client_secret.as_ref() else {
        return client.set_auth_type(AuthType::RequestBody);
    };
    let auth_type = match credentials.token_endpoint_auth_method.as_deref() {
        Some("none") => return client.set_auth_type(AuthType::RequestBody),
        Some("client_secret_post") => AuthType::RequestBody,
        _ => AuthType::BasicAuth,
    };
    client
        .set_client_secret(ClientSecret::new(secret.clone()))
        .set_auth_type(auth_type)
}

/// MCP requests carry `Authorization: Bearer <token>`; any other token type
/// (e.g. DPoP) cannot be presented that way.
fn ensure_bearer(token_type: &BasicTokenType) -> Result<(), McpError> {
    match token_type {
        BasicTokenType::Bearer => Ok(()),
        other => Err(McpError::OAuth(format!(
            "Authorization server issued a '{}' token; MCP requires Bearer tokens",
            other.as_ref()
        ))),
    }
}

/// A Client ID Metadata Document URL must be HTTPS with a path component.
fn is_valid_client_metadata_url(url: &str) -> bool {
    match url::Url::parse(url) {
        Ok(parsed) => {
            let valid = parsed.scheme() == "https" && !parsed.path().trim_matches('/').is_empty();
            if !valid {
                warn!(
                    url,
                    "Ignoring client metadata document URL: it must be HTTPS with a path"
                );
            }
            valid
        }
        Err(_) => {
            warn!(url, "Ignoring unparseable client metadata document URL");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Loopback callback server
// ---------------------------------------------------------------------------

/// Outcome of one request to the callback server.
#[derive(Debug, PartialEq, Eq)]
enum CallbackOutcome {
    /// The authorization response with the expected `state`.
    Code(String),
    /// The authorization server reported an error for this request.
    Denied(String),
    /// Not our authorization response (wrong path, missing or mismatched
    /// `state`, unrelated request): answered and discarded.
    Ignored,
}

/// Wait for the authorization response on the loopback listener.
///
/// Keeps accepting connections until one carries the expected `state` or the
/// timeout elapses. Browsers also probe `/favicon.ico` and pre-connect, and
/// the spec requires discarding responses whose `state` is missing or
/// mismatched rather than failing the login on them.
async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String, McpError> {
    let accept_loop = async {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| McpError::OAuth(format!("Failed to accept connection: {e}")))?;
            match handle_callback_connection(stream, expected_state).await {
                CallbackOutcome::Code(code) => return Ok(code),
                CallbackOutcome::Denied(error) => return Err(McpError::OAuth(error)),
                CallbackOutcome::Ignored => continue,
            }
        }
    };

    match tokio::time::timeout(CALLBACK_TIMEOUT, accept_loop).await {
        Ok(result) => result,
        Err(_) => Err(McpError::OAuth(format!(
            "OAuth callback timed out — no redirect received within {}s",
            CALLBACK_TIMEOUT.as_secs()
        ))),
    }
}

/// Read one HTTP request, classify it, and write the browser response.
async fn handle_callback_connection(mut stream: TcpStream, expected_state: &str) -> CallbackOutcome {
    let request = match read_request_head(&mut stream).await {
        Some(request) => request,
        None => return CallbackOutcome::Ignored,
    };
    let outcome = classify_callback_request(&request, expected_state);

    let (status, body) = match &outcome {
        CallbackOutcome::Code(_) => (
            "200 OK",
            "<h1>Authorization successful!</h1><p>You can close this window and return to AionUi.</p>",
        ),
        CallbackOutcome::Denied(_) => (
            "200 OK",
            "<h1>Authorization failed</h1><p>Return to AionUi for details.</p>",
        ),
        CallbackOutcome::Ignored => ("404 Not Found", "<h1>Not found</h1>"),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n<html><body>{body}</body></html>",
        body.len() + "<html><body></body></html>".len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;

    outcome
}

/// Read the request head (up to the blank line) from the callback socket.
async fn read_request_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") || buf.len() >= CALLBACK_MAX_REQUEST_BYTES {
            break;
        }
    }
    (!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned())
}

/// Classify a callback request against the expected `state`.
fn classify_callback_request(request: &str, expected_state: &str) -> CallbackOutcome {
    let Some(target) = request.lines().next().and_then(|line| {
        let mut parts = line.split_whitespace();
        (parts.next() == Some("GET")).then(|| parts.next()).flatten()
    }) else {
        return CallbackOutcome::Ignored;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return CallbackOutcome::Ignored;
    }

    let params = parse_query_params(query);
    // RFC 6749 §10.12 / MCP spec: discard results with a missing or
    // mismatched `state`, including error responses.
    if params.get("state").map(String::as_str) != Some(expected_state) {
        warn!("Discarding OAuth callback with missing or mismatched state");
        return CallbackOutcome::Ignored;
    }

    if let Some(error) = params.get("error") {
        let description = params
            .get("error_description")
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        return CallbackOutcome::Denied(format!("Authorization server returned '{error}'{description}"));
    }
    match params.get("code") {
        Some(code) if !code.is_empty() => CallbackOutcome::Code(code.clone()),
        _ => CallbackOutcome::Denied("Authorization response did not include a code".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Query parameter parsing
// ---------------------------------------------------------------------------

/// Decode an `application/x-www-form-urlencoded` query into a map (first
/// occurrence of a key wins).
fn parse_query_params(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        params.entry(key.into_owned()).or_insert_with(|| value.into_owned());
    }
    params
}

/// Parse `code` and `state` from the first line of an HTTP request.
///
/// Expects: `GET /callback?code=xxx&state=yyy HTTP/1.1`
#[cfg(test)]
fn parse_callback_query(request: &str) -> Result<(String, String), McpError> {
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| McpError::OAuth("Empty HTTP request".to_string()))?;

    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| McpError::OAuth("Malformed HTTP request line".to_string()))?;

    let query_str = path
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or_else(|| McpError::OAuth("No query parameters in callback".to_string()))?;

    let mut params = parse_query_params(query_str);
    let code = params
        .remove("code")
        .ok_or_else(|| McpError::OAuth("Missing 'code' in callback".to_string()))?;
    let state = params
        .remove("state")
        .ok_or_else(|| McpError::OAuth("Missing 'state' in callback".to_string()))?;

    Ok((code, state))
}

/// Percent-decoding for query parameter values (`+` is a space).
#[cfg(test)]
fn url_decode(input: &str) -> String {
    url::form_urlencoded::parse(format!("v={input}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_USER_ID: &str = "user-1";

    // -- parse_callback_query ------------------------------------------------

    #[test]
    fn parse_valid_callback_query() {
        let request = "GET /callback?code=abc123&state=xyz789 HTTP/1.1\r\nHost: localhost\r\n";
        let (code, state) = parse_callback_query(request).unwrap();
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn parse_callback_query_reversed_params() {
        let request = "GET /callback?state=s1&code=c1 HTTP/1.1\r\n";
        let (code, state) = parse_callback_query(request).unwrap();
        assert_eq!(code, "c1");
        assert_eq!(state, "s1");
    }

    #[test]
    fn parse_callback_query_with_extra_params() {
        let request = "GET /callback?code=c&foo=bar&state=s HTTP/1.1\r\n";
        let (code, state) = parse_callback_query(request).unwrap();
        assert_eq!(code, "c");
        assert_eq!(state, "s");
    }

    #[test]
    fn parse_callback_query_missing_code() {
        let request = "GET /callback?state=s HTTP/1.1\r\n";
        let err = parse_callback_query(request).unwrap_err();
        assert!(err.to_string().contains("Missing 'code'"));
    }

    #[test]
    fn parse_callback_query_missing_state() {
        let request = "GET /callback?code=c HTTP/1.1\r\n";
        let err = parse_callback_query(request).unwrap_err();
        assert!(err.to_string().contains("Missing 'state'"));
    }

    #[test]
    fn parse_callback_query_no_query_string() {
        let request = "GET /callback HTTP/1.1\r\n";
        let err = parse_callback_query(request).unwrap_err();
        assert!(err.to_string().contains("No query parameters"));
    }

    #[test]
    fn parse_callback_query_empty_request() {
        let err = parse_callback_query("").unwrap_err();
        assert!(err.to_string().contains("Empty HTTP request"));
    }

    // -- url_decode ----------------------------------------------------------

    #[test]
    fn url_decode_no_encoding() {
        assert_eq!(url_decode("hello"), "hello");
    }

    #[test]
    fn url_decode_percent_encoded() {
        assert_eq!(url_decode("hello%20world"), "hello world");
    }

    #[test]
    fn url_decode_plus_sign() {
        assert_eq!(url_decode("hello+world"), "hello world");
    }

    #[test]
    fn url_decode_special_characters() {
        assert_eq!(url_decode("%3D%26%3F"), "=&?");
    }

    #[test]
    fn url_decode_mixed() {
        assert_eq!(url_decode("a%20b+c%3Dd"), "a b c=d");
    }

    // -- McpOAuthService construction ----------------------------------------

    #[test]
    fn service_clone_is_independent() {
        let repo: Arc<dyn IOAuthTokenRepository> = Arc::new(MockTokenRepo);
        let http = reqwest::Client::new();
        let svc = McpOAuthService::new(repo, http);
        let _clone = svc.clone();
    }

    #[tokio::test]
    async fn clear_pending_for_user_keeps_other_user_same_oauth_state() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new());
        insert_pending_login(&svc, "user-a", "shared-state").await;
        insert_pending_login(&svc, "user-b", "shared-state").await;

        svc.clear_pending_for_user("user-a").await;

        let pending = svc.pending.lock().await;
        assert!(!pending.contains_key(&("user-a".to_string(), "shared-state".to_string())));
        assert!(pending.contains_key(&("user-b".to_string(), "shared-state".to_string())));
    }

    // -- Mock repositories ---------------------------------------------------

    async fn insert_pending_login(svc: &McpOAuthService, user_id: &str, state: &str) {
        insert_pending_login_detailed(svc, user_id, state, "https://auth.example.com/token", None).await;
    }

    async fn insert_pending_login_detailed(
        svc: &McpOAuthService,
        user_id: &str,
        state: &str,
        token_url: &str,
        resource: Option<String>,
    ) {
        let (_, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut pending = svc.pending.lock().await;
        pending.insert(
            (user_id.to_string(), state.to_string()),
            PendingLogin {
                pkce_verifier,
                auth_url: "https://auth.example.com/authorize".to_string(),
                token_url: token_url.to_string(),
                redirect_url: "http://127.0.0.1/callback".to_string(),
                resource,
                credentials: ClientCredentials {
                    client_id: DEFAULT_CLIENT_ID.to_string(),
                    client_secret: None,
                    token_endpoint_auth_method: None,
                },
                scope: None,
            },
        );
    }

    struct MockTokenRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for MockTokenRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(None)
        }

        async fn upsert(
            &self,
            _: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            unimplemented!()
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }
    }

    struct IdempotentDeleteRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for IdempotentDeleteRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(None)
        }

        async fn upsert(
            &self,
            _: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            unimplemented!()
        }

        async fn delete(&self, _: &str, url: &str) -> Result<(), aionui_db::DbError> {
            Err(aionui_db::DbError::NotFound(format!(
                "OAuth token for '{url}' not found"
            )))
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }
    }

    struct ValidTokenRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for ValidTokenRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(Some(aionui_db::models::OAuthTokenRow {
                user_id: TEST_USER_ID.to_string(),
                server_url: "https://example.com".to_string(),
                access_token: "valid_access_token".to_string(),
                refresh_token: None,
                token_type: "bearer".to_string(),
                expires_at: Some(now_ms() + 3_600_000),
                created_at: now_ms(),
                updated_at: now_ms(),
            }))
        }

        async fn upsert(
            &self,
            _: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            unimplemented!()
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec!["https://example.com".to_string()])
        }
    }

    struct ExpiredTokenRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for ExpiredTokenRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(Some(aionui_db::models::OAuthTokenRow {
                user_id: TEST_USER_ID.to_string(),
                server_url: "https://example.com".to_string(),
                access_token: "expired_token".to_string(),
                refresh_token: None,
                token_type: "bearer".to_string(),
                expires_at: Some(1000),
                created_at: 500,
                updated_at: 500,
            }))
        }

        async fn upsert(
            &self,
            _: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            unimplemented!()
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }
    }

    struct NoExpiryTokenRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for NoExpiryTokenRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(Some(aionui_db::models::OAuthTokenRow {
                user_id: TEST_USER_ID.to_string(),
                server_url: "https://example.com".to_string(),
                access_token: "no_expiry_token".to_string(),
                refresh_token: None,
                token_type: "bearer".to_string(),
                expires_at: None,
                created_at: now_ms(),
                updated_at: now_ms(),
            }))
        }

        async fn upsert(
            &self,
            _: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            unimplemented!()
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec!["https://example.com".to_string()])
        }
    }

    /// Every lookup fails — used to prove header injection degrades quietly.
    struct FailingTokenRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for FailingTokenRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Err(aionui_db::DbError::Init("db unavailable".into()))
        }

        async fn upsert(
            &self,
            _: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            unimplemented!()
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }
    }

    /// Accepts and returns every upsert — enough for refresh/exchange tests.
    struct AcceptingTokenRepo;

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for AcceptingTokenRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(None)
        }

        async fn upsert(
            &self,
            params: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            Ok(aionui_db::models::OAuthTokenRow {
                user_id: params.user_id.to_string(),
                server_url: params.server_url.to_string(),
                access_token: params.access_token.to_string(),
                refresh_token: params.refresh_token.map(str::to_string),
                token_type: params.token_type.to_string(),
                expires_at: params.expires_at,
                created_at: 0,
                updated_at: 0,
            })
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }
    }

    /// Minimal local authorization server: metadata + token endpoint. Records
    /// every token request body so tests can assert the parameters sent.
    struct MockAuthServer {
        base_url: String,
        token_bodies: Arc<Mutex<Vec<String>>>,
        /// `Authorization` header of each token request (None when absent).
        token_auth_headers: Arc<Mutex<Vec<Option<String>>>>,
        _handle: tokio::task::JoinHandle<()>,
    }

    impl MockAuthServer {
        /// Pre-RFC 9728 server: the origin is the issuer, metadata advertises
        /// PKCE S256 as the spec requires.
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let token_bodies = Arc::new(Mutex::new(Vec::new()));
            let token_auth_headers = Arc::new(Mutex::new(Vec::new()));

            let metadata_base = base_url.clone();
            let bodies = token_bodies.clone();
            let auth_headers = token_auth_headers.clone();
            let app = axum::Router::new()
                .route(
                    "/.well-known/oauth-authorization-server",
                    axum::routing::get(move || {
                        let base = metadata_base.clone();
                        async move {
                            axum::Json(serde_json::json!({
                                "issuer": base,
                                "authorization_endpoint": format!("{base}/authorize"),
                                "token_endpoint": format!("{base}/token"),
                                "code_challenge_methods_supported": ["S256"],
                            }))
                        }
                    }),
                )
                .route(
                    "/token",
                    axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                        let bodies = bodies.clone();
                        let auth_headers = auth_headers.clone();
                        async move {
                            bodies.lock().await.push(body);
                            auth_headers.lock().await.push(
                                headers
                                    .get("authorization")
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned),
                            );
                            axum::Json(serde_json::json!({
                                "access_token": "fresh_access_token",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "refresh_token": "rotated_refresh_token",
                            }))
                        }
                    }),
                );

            let handle = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            Self {
                base_url,
                token_bodies,
                token_auth_headers,
                _handle: handle,
            }
        }

        fn token_url(&self) -> String {
            format!("{}/token", self.base_url)
        }

        async fn token_request_count(&self) -> usize {
            self.token_bodies.lock().await.len()
        }

        async fn last_token_auth_header(&self) -> Option<String> {
            self.token_auth_headers
                .lock()
                .await
                .last()
                .cloned()
                .expect("expected a token request")
        }

        fn server_url(&self) -> String {
            format!("{}/mcp", self.base_url)
        }

        async fn last_token_body(&self) -> String {
            self.token_bodies
                .lock()
                .await
                .last()
                .cloned()
                .expect("expected a token request")
        }
    }

    /// Assert the form-encoded token body carries `resource=<expected>`.
    fn assert_form_resource(body: &str, expected: &str) {
        let resource = url::form_urlencoded::parse(body.as_bytes())
            .find(|(key, _)| key == "resource")
            .map(|(_, value)| value.into_owned());
        assert_eq!(resource.as_deref(), Some(expected), "token request body: {body}");
    }
    // -- Service behavior tests ----------------------------------------------

    #[tokio::test]
    async fn check_status_no_token_returns_false() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new());
        let status = svc
            .check_oauth_status(TEST_USER_ID, "https://example.com")
            .await
            .unwrap();
        assert!(!status.authenticated);
    }

    #[tokio::test]
    async fn check_status_with_valid_token() {
        let svc = McpOAuthService::new(Arc::new(ValidTokenRepo), reqwest::Client::new());
        let status = svc
            .check_oauth_status(TEST_USER_ID, "https://example.com")
            .await
            .unwrap();
        assert!(status.authenticated);
    }

    #[tokio::test]
    async fn check_status_with_expired_token() {
        let svc = McpOAuthService::new(Arc::new(ExpiredTokenRepo), reqwest::Client::new());
        let status = svc
            .check_oauth_status(TEST_USER_ID, "https://example.com")
            .await
            .unwrap();
        assert!(!status.authenticated);
    }

    #[tokio::test]
    async fn check_status_no_expiry_treated_as_valid() {
        let svc = McpOAuthService::new(Arc::new(NoExpiryTokenRepo), reqwest::Client::new());
        let status = svc
            .check_oauth_status(TEST_USER_ID, "https://example.com")
            .await
            .unwrap();
        assert!(status.authenticated);
    }

    #[tokio::test]
    async fn logout_idempotent_for_nonexistent() {
        let svc = McpOAuthService::new(Arc::new(IdempotentDeleteRepo), reqwest::Client::new());
        svc.logout(TEST_USER_ID, "https://nonexistent.example.com")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_authenticated_servers_empty() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new());
        let urls = svc.get_authenticated_servers(TEST_USER_ID).await.unwrap();
        assert!(urls.is_empty());
    }

    #[tokio::test]
    async fn get_authenticated_servers_returns_urls() {
        let svc = McpOAuthService::new(Arc::new(ValidTokenRepo), reqwest::Client::new());
        let urls = svc.get_authenticated_servers(TEST_USER_ID).await.unwrap();
        assert_eq!(urls, vec!["https://example.com"]);
    }

    #[tokio::test]
    async fn get_token_returns_none_when_no_token() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new());
        let token = svc.get_token(TEST_USER_ID, "https://example.com").await.unwrap();
        assert!(token.is_none());
    }

    #[tokio::test]
    async fn get_token_returns_access_token() {
        let svc = McpOAuthService::new(Arc::new(ValidTokenRepo), reqwest::Client::new());
        let token = svc.get_token(TEST_USER_ID, "https://example.com").await.unwrap();
        assert_eq!(token.as_deref(), Some("valid_access_token"));
    }

    #[tokio::test]
    async fn get_token_returns_expired_when_no_refresh() {
        let svc = McpOAuthService::new(Arc::new(ExpiredTokenRepo), reqwest::Client::new());
        // Expired token with no refresh_token: returns the expired token as-is.
        let token = svc.get_token(TEST_USER_ID, "https://example.com").await.unwrap();
        assert_eq!(token.as_deref(), Some("expired_token"));
    }

    // -- apply_authorization -------------------------------------------------

    #[tokio::test]
    async fn apply_authorization_adds_bearer_header() {
        let svc = McpOAuthService::new(Arc::new(ValidTokenRepo), reqwest::Client::new());
        let mut headers = HashMap::new();
        svc.apply_authorization(TEST_USER_ID, "https://example.com", &mut headers)
            .await;
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer valid_access_token")
        );
    }

    #[tokio::test]
    async fn apply_authorization_keeps_a_user_supplied_header() {
        let svc = McpOAuthService::new(Arc::new(ValidTokenRepo), reqwest::Client::new());
        // Header names are case-insensitive on the wire, so a lowercase
        // `authorization` must still win over the stored token.
        let mut headers = HashMap::from([("authorization".to_string(), "Token mine".to_string())]);
        svc.apply_authorization(TEST_USER_ID, "https://example.com", &mut headers)
            .await;
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("authorization").map(String::as_str), Some("Token mine"));
    }

    #[tokio::test]
    async fn apply_authorization_no_token_leaves_headers_untouched() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new());
        let mut headers = HashMap::from([("X-Custom".to_string(), "1".to_string())]);
        svc.apply_authorization(TEST_USER_ID, "https://example.com", &mut headers)
            .await;
        assert_eq!(headers, HashMap::from([("X-Custom".to_string(), "1".to_string())]));
    }

    #[tokio::test]
    async fn apply_authorization_repo_error_is_not_fatal() {
        let svc = McpOAuthService::new(Arc::new(FailingTokenRepo), reqwest::Client::new());
        let mut headers = HashMap::new();
        svc.apply_authorization(TEST_USER_ID, "https://example.com", &mut headers)
            .await;
        assert!(headers.is_empty());
    }

    // -- RFC 8707 resource indicator -----------------------------------------

    #[test]
    fn resource_indicator_is_canonical() {
        // Scheme and host are lowercased, fragment/query dropped.
        assert_eq!(
            McpOAuthService::resource_indicator("HTTPS://MCP.Example.COM/mcp?x=1#frag").as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        // A bare origin loses its trailing slash.
        assert_eq!(
            McpOAuthService::resource_indicator("https://mcp.example.com/").as_deref(),
            Some("https://mcp.example.com")
        );
        // Paths are preserved as-is.
        assert_eq!(
            McpOAuthService::resource_indicator("https://mcp.example.com/server/mcp").as_deref(),
            Some("https://mcp.example.com/server/mcp")
        );
        // Not an absolute http(s) URI: omitted rather than guessed.
        assert_eq!(McpOAuthService::resource_indicator("mcp.example.com"), None);
        assert_eq!(McpOAuthService::resource_indicator("ftp://mcp.example.com"), None);
    }

    /// HTTP client for tests that talk to a loopback mock server. Bypasses
    /// system proxies (`no_proxy`): a CI/dev machine may export `HTTP_PROXY`
    /// without `NO_PROXY`, which makes loopback discovery flaky.
    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn authorization_request_carries_resource_indicator() {
        let server = MockAuthServer::start().await;
        let svc = McpOAuthService::new(Arc::new(AcceptingTokenRepo), test_http_client());
        let server_url = server.server_url();

        let authorize_url = svc
            .prepare_login_flow(TEST_USER_ID, &server_url)
            .await
            .unwrap()
            .authorize_url;

        let parsed = url::Url::parse(&authorize_url).unwrap();
        let resource = parsed
            .query_pairs()
            .find(|(key, _)| key == "resource")
            .map(|(_, value)| value.into_owned());
        assert_eq!(resource.as_deref(), Some(server_url.as_str()));
    }

    #[tokio::test]
    async fn token_exchange_carries_resource_indicator() {
        let server = MockAuthServer::start().await;
        let svc = McpOAuthService::new(Arc::new(AcceptingTokenRepo), test_http_client());
        let server_url = server.server_url();
        let token_url = format!("{}/token", server.base_url);
        insert_pending_login_detailed(&svc, TEST_USER_ID, "state-1", &token_url, Some(server_url.clone())).await;

        svc.exchange_code(
            TEST_USER_ID,
            &server_url,
            "auth-code".to_string(),
            "state-1".to_string(),
        )
        .await
        .unwrap();

        assert_form_resource(&server.last_token_body().await, &server_url);
    }

    #[tokio::test]
    async fn refresh_request_carries_resource_indicator() {
        let server = MockAuthServer::start().await;
        let svc = McpOAuthService::new(Arc::new(AcceptingTokenRepo), test_http_client());
        let server_url = server.server_url();

        let token = svc
            .refresh_token(TEST_USER_ID, &server_url, "old-refresh-token")
            .await
            .unwrap();

        assert_eq!(token, "fresh_access_token");
        assert_form_resource(&server.last_token_body().await, &server_url);
    }

    // -- Persisted client registration ----------------------------------------

    /// Accepts upserts and keeps whatever client is recorded for the token.
    #[derive(Default)]
    struct ClientRecordingRepo {
        client: std::sync::Mutex<Option<OAuthClientRegistrationRow>>,
    }

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for ClientRecordingRepo {
        async fn get_by_url(
            &self,
            user_id: &str,
            server_url: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            AcceptingTokenRepo.get_by_url(user_id, server_url).await
        }

        async fn upsert(
            &self,
            params: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            AcceptingTokenRepo.upsert(params).await
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }

        async fn get_client_registration(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<OAuthClientRegistrationRow>, aionui_db::DbError> {
            Ok(self.client.lock().expect("client lock").clone())
        }

        async fn set_client_registration(
            &self,
            _: &str,
            _: &str,
            credentials: &OAuthClientRegistrationRow,
        ) -> Result<(), aionui_db::DbError> {
            *self.client.lock().expect("client lock") = Some(credentials.clone());
            Ok(())
        }
    }

    fn form_value(body: &str, key: &str) -> Option<String> {
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
    }

    #[tokio::test]
    async fn token_exchange_persists_the_client_it_used() {
        let server = MockAuthServer::start().await;
        let repo = Arc::new(ClientRecordingRepo::default());
        let svc = McpOAuthService::new(repo.clone(), test_http_client());
        let server_url = server.server_url();
        let token_url = format!("{}/token", server.base_url);
        insert_pending_login_detailed(&svc, TEST_USER_ID, "state-1", &token_url, Some(server_url.clone())).await;

        svc.exchange_code(
            TEST_USER_ID,
            &server_url,
            "auth-code".to_string(),
            "state-1".to_string(),
        )
        .await
        .unwrap();

        let stored = repo.client.lock().expect("client lock").clone();
        assert_eq!(
            stored.map(|client| client.client_id).as_deref(),
            Some(DEFAULT_CLIENT_ID)
        );
    }

    /// After a restart the in-memory registration cache is empty; the refresh
    /// must present the dynamically registered client stored with the token,
    /// not the static fallback (which the server rejects as `invalid_client`).
    #[tokio::test]
    async fn refresh_presents_the_persisted_client_after_restart() {
        let server = MockAuthServer::start().await;
        let repo = Arc::new(ClientRecordingRepo {
            client: std::sync::Mutex::new(Some(OAuthClientRegistrationRow {
                client_id: "dcr-client-42".to_owned(),
                client_secret: None,
                token_endpoint_auth_method: Some("none".to_owned()),
                token_endpoint: Some(server.token_url()),
                scope: None,
            })),
        });
        let svc = McpOAuthService::new(repo, test_http_client());
        let server_url = server.server_url();

        svc.refresh_token(TEST_USER_ID, &server_url, "old-refresh-token")
            .await
            .unwrap();

        let body = server.last_token_body().await;
        assert_eq!(
            form_value(&body, "client_id").as_deref(),
            Some("dcr-client-42"),
            "token request body: {body}"
        );
    }

    // -- Token endpoint client authentication ----------------------------------

    fn registration(method: Option<&str>, secret: Option<&str>, token_url: String) -> OAuthClientRegistrationRow {
        OAuthClientRegistrationRow {
            client_id: "client-1".to_owned(),
            client_secret: secret.map(str::to_owned),
            token_endpoint_auth_method: method.map(str::to_owned),
            token_endpoint: Some(token_url),
            scope: None,
        }
    }

    async fn refresh_with(row: OAuthClientRegistrationRow, server: &MockAuthServer) -> (String, Option<String>) {
        let repo = Arc::new(ClientRecordingRepo {
            client: std::sync::Mutex::new(Some(row)),
        });
        let svc = McpOAuthService::new(repo, test_http_client());
        svc.refresh_token(TEST_USER_ID, &server.server_url(), "rt")
            .await
            .unwrap();
        (server.last_token_body().await, server.last_token_auth_header().await)
    }

    #[tokio::test]
    async fn public_client_sends_client_id_in_body_only() {
        let server = MockAuthServer::start().await;
        let (body, auth) = refresh_with(registration(Some("none"), None, server.token_url()), &server).await;
        assert_eq!(form_value(&body, "client_id").as_deref(), Some("client-1"));
        assert_eq!(auth, None);
    }

    #[tokio::test]
    async fn client_secret_post_sends_secret_in_body() {
        let server = MockAuthServer::start().await;
        let (body, auth) = refresh_with(
            registration(Some("client_secret_post"), Some("s3cret"), server.token_url()),
            &server,
        )
        .await;
        assert_eq!(form_value(&body, "client_secret").as_deref(), Some("s3cret"));
        assert_eq!(auth, None);
    }

    #[tokio::test]
    async fn confidential_client_defaults_to_http_basic() {
        let server = MockAuthServer::start().await;
        let (body, auth) = refresh_with(registration(None, Some("s3cret"), server.token_url()), &server).await;
        assert!(
            auth.as_deref().is_some_and(|value| value.starts_with("Basic ")),
            "auth: {auth:?}"
        );
        assert_eq!(form_value(&body, "client_secret"), None);
    }

    // -- Encryption at rest ------------------------------------------------------

    /// In-memory token store that keeps exactly what the service writes.
    #[derive(Default)]
    struct StoringRepo {
        row: std::sync::Mutex<Option<aionui_db::models::OAuthTokenRow>>,
        registration: std::sync::Mutex<Option<OAuthClientRegistrationRow>>,
    }

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for StoringRepo {
        async fn get_by_url(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<aionui_db::models::OAuthTokenRow>, aionui_db::DbError> {
            Ok(self.row.lock().expect("row lock").clone())
        }

        async fn upsert(
            &self,
            params: UpsertOAuthTokenParams<'_>,
        ) -> Result<aionui_db::models::OAuthTokenRow, aionui_db::DbError> {
            let row = AcceptingTokenRepo.upsert(params).await?;
            *self.row.lock().expect("row lock") = Some(row.clone());
            Ok(row)
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), aionui_db::DbError> {
            *self.row.lock().expect("row lock") = None;
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, aionui_db::DbError> {
            Ok(vec![])
        }

        async fn get_client_registration(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<OAuthClientRegistrationRow>, aionui_db::DbError> {
            Ok(self.registration.lock().expect("registration lock").clone())
        }

        async fn set_client_registration(
            &self,
            _: &str,
            _: &str,
            registration: &OAuthClientRegistrationRow,
        ) -> Result<(), aionui_db::DbError> {
            *self.registration.lock().expect("registration lock") = Some(registration.clone());
            Ok(())
        }
    }

    const TEST_KEY: [u8; 32] = [7u8; 32];

    fn stored_row(access: &str, refresh: Option<&str>, expires_at: Option<i64>) -> aionui_db::models::OAuthTokenRow {
        aionui_db::models::OAuthTokenRow {
            user_id: TEST_USER_ID.to_owned(),
            server_url: "https://mcp.example.com/mcp".to_owned(),
            access_token: access.to_owned(),
            refresh_token: refresh.map(str::to_owned),
            token_type: "bearer".to_owned(),
            expires_at,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn tokens_and_client_secret_are_encrypted_at_rest() {
        let server = MockAuthServer::start().await;
        let repo = Arc::new(StoringRepo::default());
        let svc = McpOAuthService::new(repo.clone(), test_http_client()).with_encryption_key(TEST_KEY);
        let server_url = server.server_url();
        insert_pending_login_detailed(&svc, TEST_USER_ID, "state-1", &server.token_url(), None).await;
        svc.pending
            .lock()
            .await
            .get_mut(&(TEST_USER_ID.to_owned(), "state-1".to_owned()))
            .expect("pending login")
            .credentials
            .client_secret = Some("client-secret".to_owned());

        svc.exchange_code(TEST_USER_ID, &server_url, "code".to_owned(), "state-1".to_owned())
            .await
            .unwrap();

        let row = repo.row.lock().expect("row lock").clone().expect("stored row");
        assert!(
            row.access_token.starts_with(SEALED_PREFIX),
            "access token stored in plaintext"
        );
        assert!(!row.access_token.contains("fresh_access_token"));
        assert!(
            row.refresh_token
                .as_deref()
                .is_some_and(|t| t.starts_with(SEALED_PREFIX))
        );
        let registration = repo
            .registration
            .lock()
            .expect("registration lock")
            .clone()
            .expect("registration");
        assert!(
            registration
                .client_secret
                .as_deref()
                .is_some_and(|s| s.starts_with(SEALED_PREFIX))
        );
        assert_eq!(
            registration.token_endpoint.as_deref(),
            Some(server.token_url().as_str())
        );

        // Reading decrypts transparently.
        assert_eq!(
            svc.get_token(TEST_USER_ID, &server_url).await.unwrap().as_deref(),
            Some("fresh_access_token")
        );
    }

    #[tokio::test]
    async fn legacy_plaintext_rows_remain_readable_with_a_key() {
        let repo = Arc::new(StoringRepo::default());
        *repo.row.lock().expect("row lock") = Some(stored_row("plain-token", None, None));
        let svc = McpOAuthService::new(repo, test_http_client()).with_encryption_key(TEST_KEY);

        assert_eq!(
            svc.get_token(TEST_USER_ID, "https://mcp.example.com/mcp")
                .await
                .unwrap()
                .as_deref(),
            Some("plain-token")
        );
    }

    #[tokio::test]
    async fn sealed_token_without_key_is_an_error_not_garbage() {
        let sealing =
            McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new()).with_encryption_key(TEST_KEY);
        let sealed = sealing.seal("secret").unwrap();
        let repo = Arc::new(StoringRepo::default());
        *repo.row.lock().expect("row lock") = Some(stored_row(&sealed, None, None));
        let svc = McpOAuthService::new(repo, reqwest::Client::new());

        assert!(
            svc.get_token(TEST_USER_ID, "https://mcp.example.com/mcp")
                .await
                .is_err()
        );
    }

    // -- Refresh de-duplication --------------------------------------------------

    /// Concurrent requests that all see the same expired token must refresh it
    /// once: rotating refresh tokens make a second refresh fail.
    #[tokio::test]
    async fn concurrent_expired_lookups_refresh_once() {
        let server = MockAuthServer::start().await;
        let repo = Arc::new(StoringRepo::default());
        *repo.row.lock().expect("row lock") = Some(stored_row("stale", Some("rt-1"), Some(now_ms() - 1_000)));
        *repo.registration.lock().expect("registration lock") =
            Some(registration(Some("none"), None, server.token_url()));
        let svc = McpOAuthService::new(repo.clone(), test_http_client());
        let server_url = server.server_url();

        let mut lookups = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let svc = svc.clone();
            let server_url = server_url.clone();
            lookups.spawn(async move { svc.get_token(TEST_USER_ID, &server_url).await });
        }

        while let Some(token) = lookups.join_next().await {
            assert_eq!(token.unwrap().unwrap().as_deref(), Some("fresh_access_token"));
        }
        assert_eq!(server.token_request_count().await, 1);
        let row = repo.row.lock().expect("row lock").clone().expect("row");
        assert_eq!(row.refresh_token.as_deref(), Some("rotated_refresh_token"));
    }

    #[tokio::test]
    async fn check_status_refreshes_an_expired_token() {
        let server = MockAuthServer::start().await;
        let repo = Arc::new(StoringRepo::default());
        *repo.row.lock().expect("row lock") = Some(stored_row("stale", Some("rt-1"), Some(now_ms() - 1_000)));
        *repo.registration.lock().expect("registration lock") =
            Some(registration(Some("none"), None, server.token_url()));
        let svc = McpOAuthService::new(repo, test_http_client());

        let status = svc
            .check_oauth_status(TEST_USER_ID, &server.server_url())
            .await
            .unwrap();

        assert!(status.authenticated);
    }

    // -- Loopback callback ---------------------------------------------------------

    #[test]
    fn callback_with_matching_state_yields_code() {
        let request = "GET /callback?code=abc%2B1&state=s1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(
            classify_callback_request(request, "s1"),
            CallbackOutcome::Code("abc+1".to_owned())
        );
    }

    #[test]
    fn callback_with_wrong_or_missing_state_is_discarded() {
        assert_eq!(
            classify_callback_request("GET /callback?code=c&state=other HTTP/1.1\r\n\r\n", "s1"),
            CallbackOutcome::Ignored
        );
        assert_eq!(
            classify_callback_request("GET /callback?code=c HTTP/1.1\r\n\r\n", "s1"),
            CallbackOutcome::Ignored
        );
        // An error response without our state did not come from our request.
        assert_eq!(
            classify_callback_request("GET /callback?error=access_denied HTTP/1.1\r\n\r\n", "s1"),
            CallbackOutcome::Ignored
        );
    }

    #[test]
    fn callback_error_with_matching_state_is_reported() {
        let outcome = classify_callback_request(
            "GET /callback?error=access_denied&error_description=User+denied&state=s1 HTTP/1.1\r\n\r\n",
            "s1",
        );
        assert_eq!(
            outcome,
            CallbackOutcome::Denied("Authorization server returned 'access_denied': User denied".to_owned())
        );
    }

    #[test]
    fn unrelated_requests_are_ignored() {
        assert_eq!(
            classify_callback_request("GET /favicon.ico HTTP/1.1\r\n\r\n", "s1"),
            CallbackOutcome::Ignored
        );
        assert_eq!(
            classify_callback_request("POST /callback?code=c&state=s1 HTTP/1.1\r\n\r\n", "s1"),
            CallbackOutcome::Ignored
        );
        assert_eq!(classify_callback_request("", "s1"), CallbackOutcome::Ignored);
    }

    /// A favicon probe and a forged callback must not end the login; the real
    /// redirect arriving afterwards still completes it.
    #[tokio::test]
    async fn callback_server_waits_past_noise_for_the_real_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let waiter = tokio::spawn(async move { wait_for_callback(listener, "good-state").await });

        for path in [
            "/favicon.ico",
            "/callback?code=forged&state=bad-state",
            "/callback?code=real-code&state=good-state",
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response).await;
        }

        assert_eq!(waiter.await.unwrap().unwrap(), "real-code");
    }

    // -- Client resolution -----------------------------------------------------------

    fn metadata(cimd: Option<bool>, registration_endpoint: Option<String>) -> OAuthServerMetadata {
        OAuthServerMetadata {
            issuer: Some("https://auth.example.com".to_owned()),
            authorization_endpoint: "https://auth.example.com/authorize".to_owned(),
            token_endpoint: "https://auth.example.com/token".to_owned(),
            registration_endpoint,
            code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
            client_id_metadata_document_supported: cimd,
        }
    }

    #[tokio::test]
    async fn client_id_metadata_document_is_preferred_when_supported() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new())
            .with_client_metadata_url("https://aionui.example.com/oauth/client.json");

        let credentials = svc
            .resolve_client_credentials(
                "https://mcp.example.com/mcp",
                &metadata(Some(true), Some("https://auth.example.com/register".to_owned())),
                "http://127.0.0.1:1/callback",
                None,
            )
            .await
            .unwrap();

        assert_eq!(credentials.client_id, "https://aionui.example.com/oauth/client.json");
    }

    #[tokio::test]
    async fn static_client_id_is_used_without_cimd_or_dcr() {
        let svc = McpOAuthService::new(Arc::new(MockTokenRepo), reqwest::Client::new())
            .with_client_metadata_url("https://aionui.example.com/oauth/client.json");

        let credentials = svc
            .resolve_client_credentials(
                "https://mcp.example.com/mcp",
                &metadata(None, None),
                "http://127.0.0.1:1/callback",
                None,
            )
            .await
            .unwrap();

        assert_eq!(credentials.client_id, DEFAULT_CLIENT_ID);
    }

    #[test]
    fn client_metadata_url_must_be_https_with_a_path() {
        assert!(is_valid_client_metadata_url("https://example.com/client.json"));
        assert!(!is_valid_client_metadata_url("https://example.com/"));
        assert!(!is_valid_client_metadata_url("http://example.com/client.json"));
        assert!(!is_valid_client_metadata_url("not a url"));
    }
}
