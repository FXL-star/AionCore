//! Request-time `Authorization` resolution for the in-process aionrs agent.
//!
//! aionrs is compiled into AionCore, so its MCP transports can ask for a
//! credential before every HTTP request instead of freezing the token in the
//! server config at session-build time. That keeps long sessions working after
//! the OAuth access token is refreshed, and lets an HTTP 401 force a refresh.

use std::collections::HashMap;
use std::fmt;

use aion_mcp::transport::McpHeaderProvider;
use aionui_mcp::McpOAuthService;
use tracing::warn;

/// Supplies `Authorization: Bearer <token>` from the stored OAuth tokens of one
/// user.
///
/// Servers without a stored token simply get no header, which is why this can
/// be installed for every HTTP transport regardless of whether the server uses
/// OAuth.
pub(crate) struct McpOAuthHeaderProvider {
    oauth: McpOAuthService,
    user_id: String,
}

impl McpOAuthHeaderProvider {
    pub(crate) fn new(oauth: McpOAuthService, user_id: impl Into<String>) -> Self {
        Self {
            oauth,
            user_id: user_id.into(),
        }
    }
}

impl fmt::Debug for McpOAuthHeaderProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: this ends up in transport debug output, and
        // neither the user id nor any token state belongs in logs.
        f.debug_struct("McpOAuthHeaderProvider").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl McpHeaderProvider for McpOAuthHeaderProvider {
    async fn headers(&self, _server: &str, url: &str, force_refresh: bool) -> Option<HashMap<String, String>> {
        // `force_refresh` comes from a transport that already got HTTP 401, so
        // the local expiry check in `get_token` is not authoritative.
        let token = if force_refresh {
            self.oauth.refresh_now(&self.user_id, url).await
        } else {
            self.oauth.get_token(&self.user_id, url).await
        };

        match token {
            Ok(Some(token)) => Some(HashMap::from([("Authorization".to_owned(), format!("Bearer {token}"))])),
            Ok(None) => None,
            Err(error) => {
                // Best effort, like the session-build path: an unauthenticated
                // request is reported by the server, whereas dropping the whole
                // transport here would hide the real failure.
                warn!(server_url = url, error = %error, "MCP OAuth token lookup failed; request sent without Authorization");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aionui_db::models::OAuthTokenRow;
    use aionui_db::{DbError, IOAuthTokenRepository, UpsertOAuthTokenParams};

    use super::*;

    /// Serves one fixed token row (or none) for every URL.
    struct TokenRepo {
        row: Option<OAuthTokenRow>,
    }

    impl TokenRepo {
        fn with_token(access_token: &str) -> Self {
            Self {
                row: Some(OAuthTokenRow {
                    user_id: "user-1".to_owned(),
                    server_url: "https://mcp.example.com/mcp".to_owned(),
                    access_token: access_token.to_owned(),
                    refresh_token: None,
                    token_type: "bearer".to_owned(),
                    expires_at: Some(aionui_common::now_ms() + 3_600_000),
                    created_at: 0,
                    updated_at: 0,
                }),
            }
        }

        fn without_token() -> Self {
            Self { row: None }
        }
    }

    #[async_trait::async_trait]
    impl IOAuthTokenRepository for TokenRepo {
        async fn get_by_url(&self, _: &str, _: &str) -> Result<Option<OAuthTokenRow>, DbError> {
            Ok(self.row.clone())
        }

        async fn upsert(&self, _: UpsertOAuthTokenParams<'_>) -> Result<OAuthTokenRow, DbError> {
            unimplemented!("not needed")
        }

        async fn delete(&self, _: &str, _: &str) -> Result<(), DbError> {
            Ok(())
        }

        async fn list_authenticated_urls(&self, _: &str) -> Result<Vec<String>, DbError> {
            Ok(vec![])
        }
    }

    fn provider(repo: TokenRepo) -> McpOAuthHeaderProvider {
        McpOAuthHeaderProvider::new(McpOAuthService::new(Arc::new(repo), reqwest::Client::new()), "user-1")
    }

    #[tokio::test]
    async fn resolves_a_bearer_header_for_a_stored_token() {
        let provider = provider(TokenRepo::with_token("stored_token"));

        let headers = provider
            .headers("server", "https://mcp.example.com/mcp", false)
            .await
            .expect("headers");

        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer stored_token")
        );
    }

    /// Stdio servers share the provider but never ask for headers; a server
    /// without a stored token must simply go without `Authorization`.
    #[tokio::test]
    async fn returns_no_headers_without_a_stored_token() {
        let provider = provider(TokenRepo::without_token());

        assert!(
            provider
                .headers("server", "https://mcp.example.com/mcp", false)
                .await
                .is_none()
        );
    }

    #[test]
    fn debug_output_does_not_leak_the_user() {
        let provider = provider(TokenRepo::without_token());

        assert!(!format!("{provider:?}").contains("user-1"));
    }

    struct RefreshHarness {
        provider: McpOAuthHeaderProvider,
        repo: Arc<dyn IOAuthTokenRepository>,
        url: String,
        forms: Arc<tokio::sync::Mutex<Vec<HashMap<String, String>>>>,
        requests: Arc<tokio::sync::Mutex<Vec<String>>>,
        _db: aionui_db::Database,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for RefreshHarness {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl RefreshHarness {
        async fn new(expires_at: Option<i64>, reject_refresh: bool) -> Self {
            use axum::http::{HeaderMap, StatusCode};
            use axum::response::IntoResponse;
            use axum::routing::{get, post};
            use axum::{Form, Json, Router};
            use serde_json::{Value, json};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let url = format!("{base}/mcp");
            let forms = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let recorded_forms = forms.clone();
            let recorded_requests = requests.clone();
            let app = Router::new()
                .route(
                    "/.well-known/oauth-authorization-server",
                    get(move || {
                        let base = base.clone();
                        async move {
                            Json(json!({
                                "authorization_endpoint": format!("{base}/authorize"),
                                "token_endpoint": format!("{base}/token"),
                            }))
                        }
                    }),
                )
                .route(
                    "/token",
                    post(move |Form(form): Form<HashMap<String, String>>| {
                        let forms = recorded_forms.clone();
                        async move {
                            forms.lock().await.push(form);
                            if reject_refresh {
                                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"})))
                                    .into_response();
                            }
                            Json(json!({
                                "access_token": "fresh_access", "refresh_token": "rotated_refresh",
                                "token_type": "Bearer", "expires_in": 3600,
                            }))
                            .into_response()
                        }
                    }),
                )
                .route(
                    "/mcp",
                    post(move |headers: HeaderMap, Json(rpc): Json<Value>| {
                        let requests = recorded_requests.clone();
                        async move {
                            let token = headers
                                .get("authorization")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or_default();
                            requests.lock().await.push(token.to_owned());
                            if token != "Bearer fresh_access" {
                                return StatusCode::UNAUTHORIZED.into_response();
                            }
                            Json(json!({"jsonrpc": "2.0", "id": rpc["id"], "result": {"ok": true}})).into_response()
                        }
                    }),
                );
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let db = aionui_db::init_database_memory().await.unwrap();
            let repo: Arc<dyn IOAuthTokenRepository> =
                Arc::new(aionui_db::SqliteOAuthTokenRepository::new(db.pool().clone()));
            repo.upsert(UpsertOAuthTokenParams {
                user_id: "system_default_user",
                server_url: &url,
                access_token: "stale_access",
                refresh_token: Some("original_refresh"),
                token_type: "bearer",
                expires_at,
            })
            .await
            .unwrap();
            let oauth = McpOAuthService::new(repo.clone(), reqwest::Client::builder().no_proxy().build().unwrap());
            Self {
                provider: McpOAuthHeaderProvider::new(oauth, "system_default_user"),
                repo,
                url,
                forms,
                requests,
                _db: db,
                server,
            }
        }

        async fn call_twice(self, expect_401: bool) {
            use aion_mcp::protocol::JsonRpcRequest;
            use aion_mcp::transport::{McpTransport, streamable_http::StreamableHttpTransport};

            let provider = McpOAuthHeaderProvider::new(self.provider.oauth.clone(), self.provider.user_id.clone());
            let transport =
                StreamableHttpTransport::connect("test", &self.url, &HashMap::new(), Some(Arc::new(provider)))
                    .await
                    .unwrap();
            for id in [1, 2] {
                let response = transport
                    .request(&JsonRpcRequest::new(id, "tools/call", None))
                    .await
                    .unwrap();
                assert_eq!(response.id, Some(id));
                assert_eq!(response.result.unwrap()["ok"], true);
            }
            let forms = self.forms.lock().await;
            assert_eq!(forms.len(), 1, "one refresh serves subsequent requests");
            assert_eq!(forms[0].get("grant_type").map(String::as_str), Some("refresh_token"));
            assert_eq!(
                forms[0].get("refresh_token").map(String::as_str),
                Some("original_refresh")
            );
            assert_eq!(forms[0].get("resource"), Some(&self.url));
            let row = self
                .repo
                .get_by_url("system_default_user", &self.url)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.access_token, "fresh_access");
            assert_eq!(row.refresh_token.as_deref(), Some("rotated_refresh"));
            assert!(row.expires_at.unwrap() > aionui_common::now_ms());
            assert!(self.repo.get_by_url("user-2", &self.url).await.unwrap().is_none());
            let expected = if expect_401 {
                vec!["Bearer stale_access", "Bearer fresh_access", "Bearer fresh_access"]
            } else {
                vec!["Bearer fresh_access", "Bearer fresh_access"]
            };
            assert_eq!(*self.requests.lock().await, expected);
        }
    }

    #[tokio::test]
    async fn expired_token_is_refreshed_and_used_by_the_same_transport() {
        let harness = RefreshHarness::new(Some(aionui_common::now_ms() - 1000), false).await;
        harness.call_twice(false).await;
    }

    #[tokio::test]
    async fn server_401_refreshes_a_locally_valid_token_and_persists_rotation() {
        let harness = RefreshHarness::new(Some(aionui_common::now_ms() + 3_600_000), false).await;
        harness.call_twice(true).await;
    }

    #[tokio::test]
    async fn server_401_refreshes_a_token_without_expires_in() {
        RefreshHarness::new(None, false).await.call_twice(true).await;
    }

    #[tokio::test]
    async fn rejected_refresh_preserves_credentials_and_returns_no_header() {
        let harness = RefreshHarness::new(None, true).await;
        assert!(harness.provider.headers("test", &harness.url, true).await.is_none());
        assert_eq!(harness.forms.lock().await.len(), 1);
        let row = harness
            .repo
            .get_by_url("system_default_user", &harness.url)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.access_token, "stale_access");
        assert_eq!(row.refresh_token.as_deref(), Some("original_refresh"));
    }
}
