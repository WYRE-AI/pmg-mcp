# PMG MCP Server

An independent Model Context Protocol server for the Proxmox Mail Gateway REST API.

## Installation

```bash
npm install
npm run build
npm test
npm run lint
npm run lint:destructive
npm run smoke
```

## Configuration

Copy `.env.example` to `.env` and set:

```bash
PMG_BASE_URL=https://pmg.example.com:8006
PMG_USERNAME=mcp@pmg
PMG_PASSWORD=change-me
PMG_TOOL_TIERS=read
AUTH_MODE=env
MCP_TRANSPORT=stdio
```

In gateway mode, credentials are supplied per request through `X-PMG-Username` and `X-PMG-Password`; environment credentials are not used.

### HTTP transport hardening

- `CONDUIT_S2S_SECRET` is required for HTTP and must be at least 32 characters (`openssl rand -hex 32`). Known placeholders (`changeme`, `secret`, `placeholder`, `xxx...`, `your-secret...`) are rejected and startup fails. `MCP_ALLOW_INSECURE_DEV=1` is a local-only escape hatch for an *empty* secret: it binds 127.0.0.1 only and skips the `X-Gateway-S2S` check.
- `MCP_ALLOWED_HOSTS` is a comma-separated list of extra `Host` header values (hostname only, no port; IPv6 in brackets, e.g. `[::1]`) accepted on `/mcp`, as DNS-rebinding protection. `localhost`, `127.0.0.1` and `[::1]` are always allowed. The Host check runs when `MCP_ALLOWED_HOSTS` is set, when there is no S2S secret, or when bound to loopback; a mismatch returns `403`. Entries containing a port or unbracketed IPv6 are warned about and never match. Behind a gateway on a non-loopback bind, set `MCP_ALLOWED_HOSTS=your-gateway-hostname` to enable the check.
- The `/mcp` request body is limited to 1 MiB (`413` when exceeded).

## Tools

The server exposes exactly 88 Proxmox Mail Gateway API tools: 55 read, 17 write, and 16 admin. Tools are tiered with `read` as the default.

## Security

- Ticket authentication is cached in memory (SHA-256 keyed, LRU capped at 100 entries) for 90 minutes and refreshed after expiry or on a `401` (one re-auth retry per call).
- Path parameters are percent-encoded; empty values, `.`, `..` and values containing `/` are rejected (a strict CIDR is allowed for `cidr`). Undeclared arguments are dropped. Upstream requests time out after 30 s.
- Credentials are redacted in errors.
- TLS trust can be configured with `PMG_CA_CERT_FILE`.
- Redirects are not followed.

## Upstream license

PMG is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0), offered by Proxmox Server Solutions GmbH. This MCP is an independent client of PMG's documented REST API. No PMG code is copied; the endpoint list was derived from the public API schema. This MCP is MIT-licensed like the other `*-mcp` repositories.

Any upstream contribution would fall under the AGPL-3.0 and the Proxmox Contributor Agreement. Please ask before contributing.
