//! OAuth discovery and dynamic client registration for MCP servers.
//!
//! Implements the client side of the MCP authorization spec (2025-11-25,
//! "Authorization Server Discovery"):
//!
//! 1. An unauthenticated request to the MCP server; a `401`/`403` answer
//!    carries a `WWW-Authenticate: Bearer` challenge whose `resource_metadata`
//!    and `scope` parameters drive the rest of the flow.
//! 2. RFC 9728 protected-resource metadata, from the challenge URL when
//!    present, otherwise from the well-known URIs in the order the spec
//!    mandates (path-inserted, then root). Its `resource` must identify the
//!    server, and its `authorization_servers` names the issuer.
//! 3. RFC 8414 / OpenID Connect metadata for that issuer, probed in the
//!    spec's exact order, with the RFC 8414 §3.3 `issuer` check.
//! 4. Capability checks the spec makes mandatory before authorizing: PKCE
//!    `S256` support and HTTPS authorization-server endpoints.
//!
//! Servers that predate RFC 9728 (MCP 2025-03-26) publish no
//! protected-resource metadata. For those the MCP server's origin is treated
//! as the issuer, as that revision specified; the same capability checks
//! still apply.

use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, warn};
use url::{Host, Url};

use crate::error::McpError;

/// Opt-out for the HTTPS requirement on authorization-server endpoints.
///
/// The spec makes HTTPS mandatory; loopback hosts are always allowed for local
/// development. Set this to `1` only to talk to a non-loopback development
/// server over plain HTTP.
pub const ALLOW_INSECURE_HTTP_ENV: &str = "AIONUI_MCP_OAUTH_ALLOW_HTTP";

/// Upper bound for the unauthenticated challenge probe against the MCP server.
const CHALLENGE_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The PKCE method the spec requires (`S256`).
const PKCE_S256: &str = "S256";

/// OAuth Authorization Server Metadata (RFC 8414 / OIDC Discovery) — the
/// fields the client acts on.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthServerMetadata {
    /// RFC 8414 §2 (REQUIRED); checked against the issuer it was fetched for.
    #[serde(default)]
    pub issuer: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// RFC 7591 dynamic client registration endpoint, when supported.
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    /// Absent means "no PKCE support" (MCP spec: the client MUST refuse).
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// draft-ietf-oauth-client-id-metadata-document support flag.
    #[serde(default)]
    pub client_id_metadata_document_supported: Option<bool>,
}

/// OAuth Protected Resource Metadata (RFC 9728) — the fields the client acts on.
#[derive(Debug, Clone, Deserialize)]
struct ProtectedResourceMetadata {
    /// RFC 9728 §2 (REQUIRED): the resource identifier this document describes.
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

/// Parameters of a `WWW-Authenticate: Bearer` challenge (RFC 6750 §3,
/// RFC 9728 §5.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BearerChallenge {
    pub resource_metadata: Option<String>,
    pub scope: Option<String>,
    pub error: Option<String>,
}

/// Everything the authorization flow needs, as discovered for one MCP server.
#[derive(Debug, Clone)]
pub struct DiscoveredAuthorization {
    pub metadata: OAuthServerMetadata,
    /// Scope to request, chosen per the spec's scope selection strategy.
    /// `None` means the `scope` parameter is omitted.
    pub scope: Option<String>,
}

/// Credentials for the OAuth client used against one MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// RFC 7591 `token_endpoint_auth_method` the client was registered with.
    /// `None` defaults to `client_secret_basic` when a secret exists.
    pub token_endpoint_auth_method: Option<String>,
}

/// Successful RFC 7591 registration response — subset of fields we need.
#[derive(Debug, Deserialize)]
struct RegistrationResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
}

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

/// Protected-resource metadata URLs for an MCP endpoint, in the order the spec
/// mandates: path-inserted (`/.well-known/oauth-protected-resource/<path>`),
/// then root.
pub fn protected_resource_metadata_candidates(server_url: &str) -> Vec<String> {
    let Ok(url) = Url::parse(server_url) else {
        return Vec::new();
    };
    let Some(origin) = url_origin(&url) else {
        return Vec::new();
    };
    let path = url.path().trim_end_matches('/');

    let mut candidates = Vec::new();
    if !path.is_empty() {
        candidates.push(format!("{origin}/.well-known/oauth-protected-resource{path}"));
    }
    candidates.push(format!("{origin}/.well-known/oauth-protected-resource"));
    candidates
}

/// Authorization-server metadata URLs for an issuer, in the order the spec
/// mandates.
///
/// With a path (`https://auth.example.com/tenant1`):
/// 1. `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`
/// 2. `https://auth.example.com/.well-known/openid-configuration/tenant1`
/// 3. `https://auth.example.com/tenant1/.well-known/openid-configuration`
///
/// Without a path (`https://auth.example.com`):
/// 1. `https://auth.example.com/.well-known/oauth-authorization-server`
/// 2. `https://auth.example.com/.well-known/openid-configuration`
///
/// A path issuer never falls back to the root documents: those describe a
/// different issuer (e.g. another tenant) and would fail the issuer check.
pub fn authorization_server_metadata_candidates(issuer: &str) -> Vec<String> {
    let Ok(url) = Url::parse(issuer) else {
        return Vec::new();
    };
    let Some(origin) = url_origin(&url) else {
        return Vec::new();
    };
    let path = url.path().trim_end_matches('/');

    if path.is_empty() {
        vec![
            format!("{origin}/.well-known/oauth-authorization-server"),
            format!("{origin}/.well-known/openid-configuration"),
        ]
    } else {
        vec![
            format!("{origin}/.well-known/oauth-authorization-server{path}"),
            format!("{origin}/.well-known/openid-configuration{path}"),
            format!("{origin}{path}/.well-known/openid-configuration"),
        ]
    }
}

/// Serialize a URL's origin as `scheme://host[:port]`.
///
/// `Url::origin()` is not used because it opaquefies non-special schemes; we
/// only ever probe http(s) MCP endpoints and want a plain string.
fn url_origin(url: &Url) -> Option<String> {
    let scheme = url.scheme();
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

/// Compare two identifiers (issuer / resource) the way the specs intend:
/// scheme and host are case-insensitive (`Url` lowercases them), and a
/// trailing slash on the path is not significant.
fn same_identifier(left: &str, right: &str) -> bool {
    match (Url::parse(left), Url::parse(right)) {
        (Ok(left), Ok(right)) => {
            url_origin(&left) == url_origin(&right)
                && left.path().trim_end_matches('/') == right.path().trim_end_matches('/')
        }
        _ => false,
    }
}

/// Whether the protected-resource `resource` identifies `server_url`: the same
/// origin, and a path equal to (or a parent of) the server's path.
///
/// RFC 9728 §3.3 requires the client to reject a document whose `resource`
/// does not match; the parent allowance covers the root well-known document,
/// which the MCP spec explicitly permits for a server at a sub-path.
fn resource_identifies_server(resource: &str, server_url: &str) -> bool {
    let (Ok(resource), Ok(server)) = (Url::parse(resource), Url::parse(server_url)) else {
        return false;
    };
    if url_origin(&resource) != url_origin(&server) {
        return false;
    }
    let resource_path = resource.path().trim_end_matches('/');
    let server_path = server.path().trim_end_matches('/');
    resource_path.is_empty() || server_path == resource_path || server_path.starts_with(&format!("{resource_path}/"))
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Enforce "all authorization server endpoints MUST be served over HTTPS"
/// (MCP spec, Communication Security). Loopback is allowed for local
/// development; anything else needs the explicit opt-out.
fn ensure_secure_endpoint(name: &str, endpoint: &str, allow_insecure_http: bool) -> Result<(), McpError> {
    let url =
        Url::parse(endpoint).map_err(|e| McpError::OAuthDiscovery(format!("Invalid {name} '{endpoint}': {e}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&url) || allow_insecure_http => Ok(()),
        _ => Err(McpError::OAuthDiscovery(format!(
            "The authorization server's {name} '{endpoint}' is not served over HTTPS, which the MCP \
             authorization spec requires. Set {ALLOW_INSECURE_HTTP_ENV}=1 to allow plain HTTP for a \
             development server."
        ))),
    }
}

// ---------------------------------------------------------------------------
// WWW-Authenticate parsing
// ---------------------------------------------------------------------------

/// Parse the `Bearer` challenge out of a `WWW-Authenticate` header value.
///
/// Handles multiple challenges in one header (`Basic realm="x", Bearer ...`),
/// quoted strings with backslash escapes, and token values. Returns `None`
/// when there is no `Bearer` challenge.
pub fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let mut parser = ChallengeParser::new(header);
    while let Some(scheme) = parser.next_scheme() {
        let params = parser.params();
        if scheme.eq_ignore_ascii_case("bearer") {
            let mut challenge = BearerChallenge::default();
            for (name, value) in params {
                match name.to_ascii_lowercase().as_str() {
                    "resource_metadata" => challenge.resource_metadata = Some(value),
                    "scope" => challenge.scope = Some(value),
                    "error" => challenge.error = Some(value),
                    _ => {}
                }
            }
            return Some(challenge);
        }
    }
    None
}

/// Minimal RFC 9110 §11.6.1 challenge tokenizer.
struct ChallengeParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ChallengeParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_separators(&mut self) {
        while self.pos < self.input.len() && matches!(self.input[self.pos], b' ' | b'\t' | b',') {
            self.pos += 1;
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && matches!(self.input[self.pos], b' ' | b'\t') {
            self.pos += 1;
        }
    }

    fn token(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len() && !matches!(self.input[self.pos], b' ' | b'\t' | b',' | b'=' | b'"') {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.input[start..self.pos]).into_owned()
    }

    fn quoted(&mut self) -> String {
        // Caller has positioned us on the opening quote.
        self.pos += 1;
        let mut value = Vec::new();
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b'\\' if self.pos + 1 < self.input.len() => {
                    value.push(self.input[self.pos + 1]);
                    self.pos += 2;
                }
                b'"' => {
                    self.pos += 1;
                    break;
                }
                byte => {
                    value.push(byte);
                    self.pos += 1;
                }
            }
        }
        String::from_utf8_lossy(&value).into_owned()
    }

    fn next_scheme(&mut self) -> Option<String> {
        self.skip_separators();
        if self.pos >= self.input.len() {
            return None;
        }
        let scheme = self.token();
        (!scheme.is_empty()).then_some(scheme)
    }

    /// Read `name=value` pairs until the next challenge's scheme begins.
    fn params(&mut self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        loop {
            self.skip_separators();
            let checkpoint = self.pos;
            let name = self.token();
            if name.is_empty() {
                break;
            }
            self.skip_whitespace();
            if self.pos >= self.input.len() || self.input[self.pos] != b'=' {
                // A bare token: the scheme of the next challenge (or token68).
                self.pos = checkpoint;
                break;
            }
            self.pos += 1;
            self.skip_whitespace();
            let value = if self.pos < self.input.len() && self.input[self.pos] == b'"' {
                self.quoted()
            } else {
                self.token()
            };
            params.push((name, value));
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Discovery and registration over a shared HTTP client.
pub struct OAuthDiscovery<'a> {
    http_client: &'a reqwest::Client,
    allow_insecure_http: bool,
}

impl<'a> OAuthDiscovery<'a> {
    pub fn new(http_client: &'a reqwest::Client) -> Self {
        let allow_insecure_http = std::env::var(ALLOW_INSECURE_HTTP_ENV).is_ok_and(|value| value == "1");
        Self {
            http_client,
            allow_insecure_http,
        }
    }

    /// Override the HTTPS opt-out (tests use this instead of the process env).
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Run the full discovery sequence for an MCP server URL, starting with an
    /// unauthenticated probe for the `WWW-Authenticate` challenge.
    pub async fn discover(&self, server_url: &str) -> Result<DiscoveredAuthorization, McpError> {
        let challenge = self.probe_challenge(server_url).await;
        self.discover_with_challenge(server_url, challenge).await
    }

    /// Run discovery with an already-obtained challenge (or none).
    pub async fn discover_with_challenge(
        &self,
        server_url: &str,
        challenge: Option<BearerChallenge>,
    ) -> Result<DiscoveredAuthorization, McpError> {
        let challenge = challenge.unwrap_or_default();
        let resource_metadata = self
            .fetch_protected_resource_metadata(server_url, challenge.resource_metadata.as_deref())
            .await;

        let metadata = match &resource_metadata {
            Some(resource) => {
                self.fetch_issuer_metadata(server_url, &resource.authorization_servers)
                    .await?
            }
            None => self.fetch_legacy_metadata(server_url).await?,
        };

        self.ensure_capabilities(&metadata)?;

        // Scope selection strategy: the challenge is authoritative; otherwise
        // every `scopes_supported` entry; otherwise omit `scope`.
        let scope = challenge.scope.filter(|scope| !scope.trim().is_empty()).or_else(|| {
            resource_metadata
                .and_then(|resource| resource.scopes_supported)
                .filter(|scopes| !scopes.is_empty())
                .map(|scopes| scopes.join(" "))
        });

        Ok(DiscoveredAuthorization { metadata, scope })
    }

    /// Send one unauthenticated MCP request and parse the `Bearer` challenge
    /// from a `401`/`403` answer.
    ///
    /// A JSON-RPC `initialize` POST suits Streamable HTTP; legacy SSE servers
    /// only challenge the event-stream GET, which is tried second. Any
    /// failure just means "no challenge" — discovery then falls back to the
    /// well-known URIs, as the spec prescribes.
    pub async fn probe_challenge(&self, server_url: &str) -> Option<BearerChallenge> {
        self.probe_challenge_as(server_url, None).await
    }

    /// Like [`Self::probe_challenge`], but presenting `access_token`.
    ///
    /// Used for step-up authorization: a server that accepts the token but
    /// needs more scope answers `403` with `error="insufficient_scope"` and
    /// the scope set to request. A challenge without that error is ignored —
    /// it carries no step-up information.
    pub async fn probe_step_up_challenge(&self, server_url: &str, access_token: &str) -> Option<BearerChallenge> {
        self.probe_challenge_as(server_url, Some(access_token))
            .await
            .filter(|challenge| challenge.error.as_deref() == Some("insufficient_scope"))
    }

    async fn probe_challenge_as(&self, server_url: &str, access_token: Option<&str>) -> Option<BearerChallenge> {
        let authorize = |request: reqwest::RequestBuilder| match access_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let initialize = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "AionUi", "version": env!("CARGO_PKG_VERSION") },
            },
        });
        let post = authorize(
            self.http_client
                .post(server_url)
                .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
                .json(&initialize),
        );
        if let Some(challenge) = self.challenge_from(post).await {
            return Some(challenge);
        }

        let get = authorize(
            self.http_client
                .get(server_url)
                .header(reqwest::header::ACCEPT, "text/event-stream"),
        );
        self.challenge_from(get).await
    }

    async fn challenge_from(&self, request: reqwest::RequestBuilder) -> Option<BearerChallenge> {
        let response = request.timeout(CHALLENGE_PROBE_TIMEOUT).send().await.ok()?;
        if !matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            return None;
        }
        response
            .headers()
            .get_all(reqwest::header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(parse_bearer_challenge)
    }

    /// RFC 9728 metadata: the challenge URL when present, otherwise the
    /// well-known URIs. A document whose `resource` does not identify this
    /// server is rejected (RFC 9728 §3.3), as is one naming no authorization
    /// server.
    async fn fetch_protected_resource_metadata(
        &self,
        server_url: &str,
        challenge_url: Option<&str>,
    ) -> Option<ProtectedResourceMetadata> {
        let candidates = match challenge_url {
            Some(url) => vec![url.to_string()],
            None => protected_resource_metadata_candidates(server_url),
        };

        for candidate in candidates {
            let Some(document) = self.fetch::<ProtectedResourceMetadata>(&candidate).await else {
                continue;
            };
            match document.resource.as_deref() {
                Some(resource) if resource_identifies_server(resource, server_url) => {}
                other => {
                    warn!(
                        metadata_url = %candidate,
                        resource = ?other,
                        server_url,
                        "Ignoring protected-resource metadata that does not identify this MCP server"
                    );
                    continue;
                }
            }
            if document.authorization_servers.is_empty() {
                warn!(metadata_url = %candidate, "Protected-resource metadata names no authorization server");
                continue;
            }
            return Some(document);
        }
        None
    }

    /// Authorization-server metadata for the first advertised issuer that
    /// serves a valid document (RFC 9728 §7.6 leaves the choice to the client).
    async fn fetch_issuer_metadata(
        &self,
        server_url: &str,
        issuers: &[String],
    ) -> Result<OAuthServerMetadata, McpError> {
        for issuer in issuers {
            for candidate in authorization_server_metadata_candidates(issuer) {
                let Some(metadata) = self.fetch::<OAuthServerMetadata>(&candidate).await else {
                    continue;
                };
                // RFC 8414 §3.3: the `issuer` MUST be identical to the issuer
                // the document was requested for; otherwise it is not used.
                match metadata.issuer.as_deref() {
                    Some(found) if same_identifier(found, issuer) => return Ok(metadata),
                    found => warn!(
                        metadata_url = %candidate,
                        expected_issuer = %issuer,
                        found_issuer = ?found,
                        "Ignoring authorization-server metadata with a mismatched issuer"
                    ),
                }
            }
        }

        Err(McpError::OAuthDiscovery(format!(
            "Could not discover authorization-server metadata for '{server_url}'. Its protected-resource \
             metadata names {issuers:?}, but none of them published RFC 8414 or OpenID Connect metadata \
             with a matching issuer."
        )))
    }

    /// Discovery for servers that predate RFC 9728 (MCP 2025-03-26): the MCP
    /// server's origin acts as the issuer. Path-based spellings follow for
    /// servers that published metadata under their endpoint path.
    async fn fetch_legacy_metadata(&self, server_url: &str) -> Result<OAuthServerMetadata, McpError> {
        let mut candidates = Vec::new();
        if let Ok(url) = Url::parse(server_url)
            && let Some(origin) = url_origin(&url)
        {
            candidates.extend(authorization_server_metadata_candidates(&origin));
            let path = url.path().trim_end_matches('/');
            if !path.is_empty() {
                candidates.push(format!("{origin}/.well-known/oauth-authorization-server{path}"));
                candidates.push(format!("{origin}/.well-known/openid-configuration{path}"));
                candidates.push(format!("{origin}{path}/.well-known/oauth-authorization-server"));
                candidates.push(format!("{origin}{path}/.well-known/openid-configuration"));
            }
        }

        for candidate in candidates {
            if let Some(metadata) = self.fetch::<OAuthServerMetadata>(&candidate).await {
                debug!(
                    server_url,
                    metadata_url = %candidate,
                    "Using authorization-server metadata without protected-resource metadata (pre-RFC 9728 server)"
                );
                return Ok(metadata);
            }
        }

        Err(McpError::OAuthDiscovery(format!(
            "Could not discover OAuth endpoints for '{server_url}'. The server did not answer with a \
             WWW-Authenticate resource_metadata challenge and published neither RFC 9728 \
             protected-resource metadata nor RFC 8414 / OpenID Connect metadata at any well-known location."
        )))
    }

    /// Checks the spec makes mandatory before an authorization request.
    fn ensure_capabilities(&self, metadata: &OAuthServerMetadata) -> Result<(), McpError> {
        // "MCP clients MUST verify PKCE support before proceeding": absent
        // `code_challenge_methods_supported` means no PKCE support.
        let supports_s256 = metadata
            .code_challenge_methods_supported
            .as_ref()
            .is_some_and(|methods| methods.iter().any(|method| method == PKCE_S256));
        if !supports_s256 {
            return Err(McpError::OAuthDiscovery(format!(
                "The authorization server does not advertise PKCE S256 support \
                 (code_challenge_methods_supported = {:?}); the MCP authorization spec requires the \
                 client to refuse to proceed.",
                metadata.code_challenge_methods_supported
            )));
        }

        ensure_secure_endpoint(
            "authorization endpoint",
            &metadata.authorization_endpoint,
            self.allow_insecure_http,
        )?;
        ensure_secure_endpoint("token endpoint", &metadata.token_endpoint, self.allow_insecure_http)?;
        if let Some(registration) = metadata.registration_endpoint.as_deref() {
            ensure_secure_endpoint("registration endpoint", registration, self.allow_insecure_http)?;
        }
        Ok(())
    }

    /// Register a public OAuth client via RFC 7591 dynamic client registration.
    pub async fn register_client(
        &self,
        registration_endpoint: &str,
        redirect_uri: &str,
        scope: Option<&str>,
    ) -> Result<ClientCredentials, McpError> {
        let mut body = serde_json::json!({
            "client_name": "AionUi",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        });
        if let Some(scope) = scope {
            body["scope"] = serde_json::Value::String(scope.to_owned());
        }

        let resp = self
            .http_client
            .post(registration_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| McpError::OAuth(format!("Client registration request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(McpError::OAuth(format!(
                "Client registration at '{registration_endpoint}' returned {status}"
            )));
        }

        let registered: RegistrationResponse = resp
            .json()
            .await
            .map_err(|e| McpError::OAuth(format!("Failed to parse client registration response: {e}")))?;

        Ok(ClientCredentials {
            client_id: registered.client_id,
            client_secret: registered.client_secret,
            token_endpoint_auth_method: registered.token_endpoint_auth_method,
        })
    }

    /// GET and deserialize a metadata document, returning `None` on any failure.
    async fn fetch<T: serde::de::DeserializeOwned>(&self, url: &str) -> Option<T> {
        let resp = self.http_client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<T>().await.ok()
    }
}

#[cfg(test)]
#[path = "oauth_discovery_test.rs"]
mod oauth_discovery_test;
