use std::sync::Arc;

use tokio::sync::Mutex;

use super::*;

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

#[test]
fn protected_resource_candidates_follow_spec_order() {
    assert_eq!(
        protected_resource_metadata_candidates("https://example.com/public/mcp"),
        vec![
            "https://example.com/.well-known/oauth-protected-resource/public/mcp",
            "https://example.com/.well-known/oauth-protected-resource",
        ]
    );
    assert_eq!(
        protected_resource_metadata_candidates("https://example.com/"),
        vec!["https://example.com/.well-known/oauth-protected-resource"]
    );
    assert!(protected_resource_metadata_candidates("not a url").is_empty());
}

#[test]
fn issuer_with_path_uses_the_three_spec_locations_only() {
    assert_eq!(
        authorization_server_metadata_candidates("https://auth.example.com/tenant1"),
        vec![
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
            "https://auth.example.com/.well-known/openid-configuration/tenant1",
            "https://auth.example.com/tenant1/.well-known/openid-configuration",
        ]
    );
}

#[test]
fn issuer_without_path_uses_the_two_spec_locations() {
    assert_eq!(
        authorization_server_metadata_candidates("https://auth.example.com/"),
        vec![
            "https://auth.example.com/.well-known/oauth-authorization-server",
            "https://auth.example.com/.well-known/openid-configuration",
        ]
    );
}

#[test]
fn candidates_preserve_non_default_port() {
    assert_eq!(
        authorization_server_metadata_candidates("http://127.0.0.1:8931")[0],
        "http://127.0.0.1:8931/.well-known/oauth-authorization-server"
    );
}

#[test]
fn resource_must_identify_the_server() {
    let server = "https://mcp.example.com/server/mcp";
    assert!(resource_identifies_server("https://mcp.example.com/server/mcp", server));
    assert!(resource_identifies_server(
        "https://MCP.example.com/server/mcp/",
        server
    ));
    // Root document for a sub-path server.
    assert!(resource_identifies_server("https://mcp.example.com", server));
    assert!(resource_identifies_server("https://mcp.example.com/server", server));
    // A different server, or a sibling path that only shares a prefix.
    assert!(!resource_identifies_server(
        "https://evil.example.com/server/mcp",
        server
    ));
    assert!(!resource_identifies_server(
        "https://mcp.example.com/server/mcp-other",
        server
    ));
    assert!(!resource_identifies_server("https://mcp.example.com/other", server));
    assert!(!resource_identifies_server("not a url", server));
}

#[test]
fn issuer_comparison_ignores_case_and_trailing_slash_only() {
    assert!(same_identifier("https://Auth.Example.com/", "https://auth.example.com"));
    assert!(same_identifier(
        "https://auth.example.com/t1/",
        "https://auth.example.com/t1"
    ));
    assert!(!same_identifier(
        "https://auth.example.com/t1",
        "https://auth.example.com/t2"
    ));
    assert!(!same_identifier("http://auth.example.com", "https://auth.example.com"));
}

#[test]
fn https_is_required_except_for_loopback_or_opt_out() {
    assert!(ensure_secure_endpoint("token endpoint", "https://auth.example.com/token", false).is_ok());
    assert!(ensure_secure_endpoint("token endpoint", "http://127.0.0.1:9000/token", false).is_ok());
    assert!(ensure_secure_endpoint("token endpoint", "http://localhost:9000/token", false).is_ok());
    assert!(ensure_secure_endpoint("token endpoint", "http://[::1]:9000/token", false).is_ok());
    assert!(ensure_secure_endpoint("token endpoint", "http://auth.example.com/token", false).is_err());
    assert!(ensure_secure_endpoint("token endpoint", "http://auth.example.com/token", true).is_ok());
    assert!(ensure_secure_endpoint("token endpoint", "ftp://auth.example.com/token", true).is_err());
}

// ---------------------------------------------------------------------------
// WWW-Authenticate parsing
// ---------------------------------------------------------------------------

#[test]
fn parses_spec_example_challenge() {
    let challenge = parse_bearer_challenge(
        r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read""#,
    )
    .expect("bearer challenge");
    assert_eq!(
        challenge.resource_metadata.as_deref(),
        Some("https://mcp.example.com/.well-known/oauth-protected-resource")
    );
    assert_eq!(challenge.scope.as_deref(), Some("files:read"));
    assert_eq!(challenge.error, None);
}

#[test]
fn parses_insufficient_scope_challenge_with_spaces_and_escapes() {
    let challenge = parse_bearer_challenge(
        r#"bearer error="insufficient_scope", scope="files:read files:write", error_description="needs \"write\"""#,
    )
    .expect("bearer challenge");
    assert_eq!(challenge.error.as_deref(), Some("insufficient_scope"));
    assert_eq!(challenge.scope.as_deref(), Some("files:read files:write"));
}

#[test]
fn finds_bearer_among_multiple_challenges() {
    let challenge =
        parse_bearer_challenge(r#"Basic realm="legacy", Bearer realm="mcp", scope=read"#).expect("bearer challenge");
    assert_eq!(challenge.scope.as_deref(), Some("read"));
}

#[test]
fn non_bearer_challenge_yields_none() {
    assert_eq!(parse_bearer_challenge(r#"Basic realm="x""#), None);
    assert_eq!(parse_bearer_challenge(""), None);
}

#[test]
fn bare_bearer_challenge_has_no_parameters() {
    assert_eq!(parse_bearer_challenge("Bearer"), Some(BearerChallenge::default()));
}

// ---------------------------------------------------------------------------
// Metadata parsing
// ---------------------------------------------------------------------------

#[test]
fn metadata_parses_optional_fields() {
    let metadata: OAuthServerMetadata = serde_json::from_str(
        r#"{"issuer":"https://a.example","authorization_endpoint":"https://a.example/auth",
            "token_endpoint":"https://a.example/token",
            "registration_endpoint":"https://a.example/register",
            "code_challenge_methods_supported":["S256"],
            "client_id_metadata_document_supported":true}"#,
    )
    .unwrap();
    assert_eq!(
        metadata.registration_endpoint.as_deref(),
        Some("https://a.example/register")
    );
    assert_eq!(metadata.code_challenge_methods_supported, Some(vec!["S256".to_owned()]));
    assert_eq!(metadata.client_id_metadata_document_supported, Some(true));
}

#[test]
fn metadata_without_optional_fields_still_parses() {
    let metadata: OAuthServerMetadata = serde_json::from_str(
        r#"{"authorization_endpoint":"https://a.example/auth","token_endpoint":"https://a.example/token"}"#,
    )
    .unwrap();
    assert_eq!(metadata.issuer, None);
    assert_eq!(metadata.code_challenge_methods_supported, None);
}

// ---------------------------------------------------------------------------
// End-to-end discovery against a local MCP + authorization server
// ---------------------------------------------------------------------------

/// How the mock MCP server advertises its protected-resource metadata.
#[derive(Clone, Copy)]
enum PrmMode {
    /// Only through `WWW-Authenticate: resource_metadata=...` (custom path).
    ChallengeOnly,
    /// Only at the path-inserted well-known URI; no challenge header.
    WellKnown,
    /// Not at all (pre-RFC 9728 server).
    None,
}

struct MockSpec {
    prm: PrmMode,
    /// `resource` value in the protected-resource metadata; `None` = the MCP URL.
    prm_resource: Option<String>,
    challenge_scope: Option<&'static str>,
    scopes_supported: Option<Vec<&'static str>>,
    /// Issuer path on the mock server (e.g. "/tenant1"), or "" for root.
    issuer_path: &'static str,
    /// Override for the `issuer` value inside the AS metadata.
    issuer_override: Option<String>,
    pkce_methods: Option<Vec<&'static str>>,
}

impl Default for MockSpec {
    fn default() -> Self {
        Self {
            prm: PrmMode::ChallengeOnly,
            prm_resource: None,
            challenge_scope: None,
            scopes_supported: None,
            issuer_path: "/tenant1",
            issuer_override: None,
            pkce_methods: Some(vec!["S256"]),
        }
    }
}

struct MockServers {
    base: String,
    requested: Arc<Mutex<Vec<String>>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockServers {
    fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base)
    }

    fn issuer(&self, spec: &MockSpec) -> String {
        format!("{}{}", self.base, spec.issuer_path)
    }

    async fn requested(&self) -> Vec<String> {
        self.requested.lock().await.clone()
    }
}

/// One loopback server playing both MCP server and authorization server.
/// Every request path is recorded so tests can assert the probe order.
async fn start_mock(spec: MockSpec) -> MockServers {
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requested = Arc::new(Mutex::new(Vec::new()));

    let spec = Arc::new(spec);
    let state = (base.clone(), Arc::clone(&spec), Arc::clone(&requested));

    let handler = move |uri: Uri| {
        let (base, spec, requested) = state.clone();
        async move {
            let path = uri.path().to_owned();
            requested.lock().await.push(path.clone());

            let mcp_url = format!("{base}/mcp");
            let issuer = format!("{base}{}", spec.issuer_path);
            let challenge_prm = format!("{base}/custom/prm");
            let path_inserted_prm = "/.well-known/oauth-protected-resource/mcp";
            let as_metadata_path = format!("/.well-known/oauth-authorization-server{}", spec.issuer_path);

            let prm_document = || {
                let mut doc = serde_json::json!({
                    "resource": spec.prm_resource.clone().unwrap_or_else(|| mcp_url.clone()),
                    "authorization_servers": [issuer.clone()],
                });
                if let Some(scopes) = &spec.scopes_supported {
                    doc["scopes_supported"] = serde_json::json!(scopes);
                }
                axum::Json(doc).into_response()
            };

            let response: Response = if path == "/mcp" {
                let mut headers = HeaderMap::new();
                if matches!(spec.prm, PrmMode::ChallengeOnly) {
                    let mut value = format!(r#"Bearer resource_metadata="{challenge_prm}""#);
                    if let Some(scope) = spec.challenge_scope {
                        value.push_str(&format!(r#", scope="{scope}""#));
                    }
                    headers.insert("www-authenticate", value.parse().unwrap());
                } else {
                    headers.insert("www-authenticate", "Bearer".parse().unwrap());
                }
                (StatusCode::UNAUTHORIZED, headers).into_response()
            } else if (path == "/custom/prm" && matches!(spec.prm, PrmMode::ChallengeOnly))
                || (path == path_inserted_prm && matches!(spec.prm, PrmMode::WellKnown))
            {
                prm_document()
            } else if path == as_metadata_path
                || (matches!(spec.prm, PrmMode::None) && path == "/.well-known/oauth-authorization-server")
            {
                let mut doc = serde_json::json!({
                    "issuer": spec.issuer_override.clone().unwrap_or_else(|| issuer.clone()),
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                    "registration_endpoint": format!("{base}/register"),
                });
                if let Some(methods) = &spec.pkce_methods {
                    doc["code_challenge_methods_supported"] = serde_json::json!(methods);
                }
                axum::Json(doc).into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            };
            response
        }
    };

    let app = axum::Router::new().fallback(handler);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    MockServers {
        base,
        requested,
        _handle: handle,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn challenge_resource_metadata_drives_discovery() {
    let spec = MockSpec {
        challenge_scope: Some("files:read"),
        scopes_supported: Some(vec!["files:read", "files:write"]),
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    let discovered = OAuthDiscovery::new(&client).discover(&mock.mcp_url()).await.unwrap();

    assert_eq!(discovered.metadata.token_endpoint, format!("{}/token", mock.base));
    // The challenge scope is authoritative over scopes_supported.
    assert_eq!(discovered.scope.as_deref(), Some("files:read"));
    let requested = mock.requested().await;
    assert!(
        requested.contains(&"/custom/prm".to_owned()),
        "requested: {requested:?}"
    );
    assert!(
        !requested
            .iter()
            .any(|path| path.starts_with("/.well-known/oauth-protected-resource")),
        "well-known PRM must not be probed when the challenge names it: {requested:?}"
    );
}

#[tokio::test]
async fn well_known_fallback_and_scopes_supported() {
    let spec = MockSpec {
        prm: PrmMode::WellKnown,
        scopes_supported: Some(vec!["read", "write"]),
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    let discovered = OAuthDiscovery::new(&client).discover(&mock.mcp_url()).await.unwrap();

    assert_eq!(discovered.scope.as_deref(), Some("read write"));
}

#[tokio::test]
async fn scope_is_omitted_without_challenge_scope_or_scopes_supported() {
    let mock = start_mock(MockSpec::default()).await;
    let client = http_client();

    let discovered = OAuthDiscovery::new(&client).discover(&mock.mcp_url()).await.unwrap();

    assert_eq!(discovered.scope, None);
}

#[tokio::test]
async fn path_issuer_is_probed_in_spec_order_without_root_fallback() {
    // The AS only serves OIDC path-appended metadata, so every earlier
    // location is probed first; root documents must never be requested.
    let spec = MockSpec {
        issuer_path: "/tenant1",
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let issuer = mock.issuer(&MockSpec::default());
    let client = http_client();

    // Point discovery at an issuer whose metadata is missing entirely, so all
    // candidate paths get requested.
    let result = OAuthDiscovery::new(&client)
        .fetch_issuer_metadata(&mock.mcp_url(), &[format!("{issuer}-missing")])
        .await;

    assert!(result.is_err());
    let requested = mock.requested().await;
    assert_eq!(
        requested,
        vec![
            "/.well-known/oauth-authorization-server/tenant1-missing",
            "/.well-known/openid-configuration/tenant1-missing",
            "/tenant1-missing/.well-known/openid-configuration",
        ]
    );
}

#[tokio::test]
async fn mismatched_issuer_is_rejected() {
    let spec = MockSpec {
        issuer_override: Some("https://attacker.example".to_owned()),
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    let err = OAuthDiscovery::new(&client)
        .discover(&mock.mcp_url())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("matching issuer"), "unexpected error: {err}");
}

#[tokio::test]
async fn resource_metadata_for_another_server_is_rejected() {
    let spec = MockSpec {
        prm_resource: Some("https://other.example.com/mcp".to_owned()),
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    // With the PRM rejected the server looks pre-RFC 9728, and the legacy
    // probe finds nothing at the origin.
    let err = OAuthDiscovery::new(&client)
        .discover(&mock.mcp_url())
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("Could not discover OAuth endpoints"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn missing_pkce_support_refuses_to_proceed() {
    let spec = MockSpec {
        pkce_methods: None,
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    let err = OAuthDiscovery::new(&client)
        .discover(&mock.mcp_url())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("PKCE S256"), "unexpected error: {err}");
}

#[tokio::test]
async fn plain_pkce_only_refuses_to_proceed() {
    let spec = MockSpec {
        pkce_methods: Some(vec!["plain"]),
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    assert!(OAuthDiscovery::new(&client).discover(&mock.mcp_url()).await.is_err());
}

#[tokio::test]
async fn pre_rfc9728_server_uses_origin_as_issuer() {
    let spec = MockSpec {
        prm: PrmMode::None,
        issuer_path: "",
        ..MockSpec::default()
    };
    let mock = start_mock(spec).await;
    let client = http_client();

    let discovered = OAuthDiscovery::new(&client).discover(&mock.mcp_url()).await.unwrap();

    assert_eq!(
        discovered.metadata.authorization_endpoint,
        format!("{}/authorize", mock.base)
    );
}
