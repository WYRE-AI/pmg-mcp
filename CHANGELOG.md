# Changelog

## [Unreleased]

### Security
- Gateway mode requires `CONDUIT_S2S_SECRET` >= 32 chars and rejects placeholders at startup.
- `MCP_ALLOWED_HOSTS` Host-header check (DNS-rebinding protection) before `/mcp`; 1 MiB body limit (413).
- Path parameters are now actually substituted (previously `{param}` never matched) with percent-encoding and rejection of empty/`.`/`..`/`/` values.
- Exactly one re-auth retry on `401`; ticket cache keyed by SHA-256 with LRU cap (100) and expiry sweep; undeclared arguments are no longer forwarded.
- CI reusable-workflow refs point at the `wyre-technology`/`WYRE-AI` orgs; `mcp-assert.yml` has `permissions: contents: read`; added `.dockerignore`.
- Removed Driversnote copy-paste leftovers (`DRIVERSNOTE_TOOL_TIERS`, names, log lines).
- 30 s upstream timeout, CA-aware ticket fetch, cached undici Agent, guarded ticket JSON parse.

### Fixed
- HTTP `AUTH_MODE=gateway`: per-request gateway credentials now reach the tool handler (the CallTool handler previously read env credentials); gateway mode never falls back to env.
- Gateway header lookup is case-insensitive (Node lowercases incoming header names).
- Ticket cache is keyed per (baseUrl, user, password) so tickets are never shared across gateway users.

### Added
- Gateway-mode regression tests and an HTTP gateway smoke check; `.gitleaks.toml` allowlisting fake test credentials.
