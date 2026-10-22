-- Authorization context a token was issued under, needed to refresh it
-- without re-running discovery.
--
-- * client_token_endpoint_auth_method: RFC 7591 method the client registered
--   with (`none`, `client_secret_basic`, `client_secret_post`).
-- * token_endpoint: where the refresh request goes. Re-discovery may need an
--   unauthenticated round-trip to the MCP server for its WWW-Authenticate
--   challenge, which a per-request refresh should not pay.
-- * scope: the scope the user granted, re-sent on step-up.
--
-- All NULL on rows written before this migration; refresh then falls back to
-- discovery and the token-endpoint default.
ALTER TABLE oauth_tokens ADD COLUMN client_token_endpoint_auth_method TEXT;
ALTER TABLE oauth_tokens ADD COLUMN token_endpoint TEXT;
ALTER TABLE oauth_tokens ADD COLUMN scope TEXT;
