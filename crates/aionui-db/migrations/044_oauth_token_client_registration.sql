-- OAuth client a token was issued to.
--
-- A refresh token is bound to the client that obtained it. Clients created
-- through RFC 7591 dynamic registration were only cached in memory, so after a
-- restart refreshes fell back to the static client id and the authorization
-- server rejected them with `invalid_client`.
--
-- Stored on the token row (not a per-server table) because the registration
-- shares the token's lifecycle: it is written by the login that issued the
-- token and removed by the logout that deletes it. NULL means "unknown" (rows
-- written before this migration); such tokens keep the in-memory fallback.
ALTER TABLE oauth_tokens ADD COLUMN client_id TEXT;
ALTER TABLE oauth_tokens ADD COLUMN client_secret TEXT;
