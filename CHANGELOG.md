# Changelog

## [Unreleased]

### Fixed
- HTTP `AUTH_MODE=gateway`: per-request gateway credentials now reach the tool handler (the CallTool handler previously read env credentials); gateway mode never falls back to env.
- Gateway header lookup is case-insensitive (Node lowercases incoming header names).
- Ticket cache is keyed per (baseUrl, user, password) so tickets are never shared across gateway users.

### Added
- Gateway-mode regression tests and an HTTP gateway smoke check; `.gitleaks.toml` allowlisting fake test credentials.
