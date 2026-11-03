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

## Tools

The server exposes exactly 88 Proxmox Mail Gateway API tools: 55 read, 17 write, and 16 admin. Tools are tiered with `read` as the default.

## Security

- Ticket authentication is cached in memory for 90 minutes and refreshed after expiry or on a `401`.
- Credentials are redacted in errors.
- TLS trust can be configured with `PMG_CA_CERT_FILE`.
- Redirects are not followed.

## Upstream license

PMG is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0), offered by Proxmox Server Solutions GmbH. This MCP is an independent client of PMG's documented REST API. No PMG code is copied; the endpoint list was derived from the public API schema. This MCP is MIT-licensed like the other `*-mcp` repositories.

Any upstream contribution would fall under the AGPL-3.0 and the Proxmox Contributor Agreement. Please ask before contributing.
