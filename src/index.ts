#!/usr/bin/env node
/**
 * Driversnote MCP Server
 *
 * One MCP tool per operation of the Proxmox Mail Gateway API.
 * 55 read + 17 write + 16 admin = 88 tools. Tools are grouped by tier
 * (read | write | admin); only the tiers listed in PMG_TOOL_TIERS
 * (default "read") are listed or callable.
 *
 * Transports:
 * - stdio (default): reads PMG_USERNAME and PMG_PASSWORD from the environment.
 * - http: stateless Streamable HTTP (a fresh Server + Transport per POST /mcp).
 *
 * Auth modes (HTTP only):
 * - env (default): PMG_USERNAME and PMG_PASSWORD from the process environment.
 * - gateway: the per-user credentials arrive in the `X-PMG-Username` and
 *   `X-PMG-Password` request headers on every request. Gateway mode never
 *   falls back to environment credentials.
 *
 * HTTP transport refuses to start unless CONDUIT_S2S_SECRET is set to a real
 * value (known placeholders are rejected). MCP_ALLOW_INSECURE_DEV=1 is a
 * local-only escape hatch for an empty secret: it logs a warning, does not
 * enforce X-Gateway-S2S, and listens on 127.0.0.1 only. /health and /healthz
 * are unauthenticated and never read credentials.
 */

import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, ServerResponse, Server as HttpServer } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { listTools, callTool } from "./utils/handler.js";
import type { PmgCredentials } from "./utils/types.js";
import { getCredentials, getBaseUrl } from "./utils/client.js";
import { getEnabledTiers } from "./tiers.js";
import { logger } from "./utils/logger.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";

/**
 * Public example values. A copied placeholder must not verify as a real secret.
 * Matched after trim + lowercase, so "Change-Me" is the same as "change-me".
 */
// SECURITY-REVIEW: placeholder deny-list for the S2S secret.
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  "replace-with-a-real-secret",
  "your-s2s-secret",
  "your-secret",
  "changeme",
  "change-me",
  "placeholder",
  "secret",
  "example",
  "replace-me",
  "s2s-secret",
]);

const LOOPBACK_HOST = "127.0.0.1";

const MISSING_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. " +
  "Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), " +
  "or set MCP_ALLOW_INSECURE_DEV=1 for local development only.";

const PLACEHOLDER_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
  "Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value.";

const INSECURE_DEV_WARNING =
  "SECURITY WARNING: CONDUIT_S2S_SECRET is empty and MCP_ALLOW_INSECURE_DEV=1. " +
  "HTTP /mcp is starting with service-to-service authentication DISABLED, bound to 127.0.0.1 only. " +
  "Local development only; do not expose this port.";

function refuseStart(message: string): never {
  logger.error(message);
  process.exit(1);
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

/** 127.0.0.1, the rest of 127.0.0.0/8, localhost, and ::1. */
function isLoopbackBindHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, "$1");
  if (normalized === "localhost" || normalized === "::1") return true;
  const bare = normalized.startsWith("::ffff:") ? normalized.slice("::ffff:".length) : normalized;
  const parts = bare.split(".");
  if (parts.length !== 4) return false;
  if (parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  return parts[0] === "127";
}

/**
 * Fail closed. A known placeholder is never a configured secret, including
 * when MCP_ALLOW_INSECURE_DEV=1 is also set. Empty is the only case the dev
 * flag may bypass, and that bypass does not check X-Gateway-S2S.
 * The secret value is never written to logs.
 */
function resolveS2sSecret(env: NodeJS.ProcessEnv = process.env): { secret: string; insecureDev: boolean } {
  // SECURITY-REVIEW: S2S secret resolution (fail closed; dev bypass only when the secret is empty).
  const raw = (env.CONDUIT_S2S_SECRET ?? "").trim();
  if (raw && KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase())) {
    refuseStart(PLACEHOLDER_S2S_SECRET_ERROR);
  }
  if (raw) return { secret: raw, insecureDev: false };
  if (env.MCP_ALLOW_INSECURE_DEV === "1") {
    return { secret: "", insecureDev: true };
  }
  refuseStart(MISSING_S2S_SECRET_ERROR);
}

/**
 * No real secret: force 127.0.0.1, even when MCP_HTTP_HOST is a wider address
 * such as 0.0.0.0. A real secret honors MCP_HTTP_HOST. When that variable is
 * unset the bind is 127.0.0.1; the container image sets 0.0.0.0 explicitly.
 */
function resolveBindHost(s2sSecret: string, env: NodeJS.ProcessEnv = process.env): string {
  // SECURITY-REVIEW: network exposure; unauthenticated dev mode is loopback-only.
  const configured = (env.MCP_HTTP_HOST ?? "").trim();
  if (s2sSecret) return configured || LOOPBACK_HOST;
  if (configured && !isLoopbackBindHost(configured)) {
    logger.error(
      `WARNING: MCP_HTTP_HOST=${configured} is not a loopback address. ` +
        "MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET cannot listen there. " +
        `Binding ${LOOPBACK_HOST} only.`,
    );
  }
  return LOOPBACK_HOST;
}

/**
 * Create a fresh MCP Server instance with all request handlers registered.
 *
 * Called ONCE for stdio mode, and ONCE PER HTTP REQUEST for the Streamable
 * HTTP transport. A fresh Server (and Transport) per request keeps the HTTP
 * transport stateless so every client can initialize independently.
 */
export function createFreshServer(): Server {
  const server = new Server(
    { name: "mcp-server-pmg", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.onerror = (error) => {
    logger.error("MCP server error", { error: error instanceof Error ? error.message : String(error) });
  };

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: listTools() }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    // Log the tool name only: arguments may contain personal data.
    logger.info("Tool call received", { tool: name });
    try {
      const credentials = getCredentials();
      if ("error" in credentials) {
        return { content: [{ type: "text", text: `Error: ${credentials.error}` }], isError: true };
      }
      return await callTool(name, (args ?? {}) as Record<string, unknown>, credentials);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error("Tool call failed", { tool: name, error: message });
      return { content: [{ type: "text" as const, text: `Error: ${message}` }], isError: true };
    }
  });

  return server;
}

/**
 * Handle a single MCP HTTP request with a fresh, stateless Server + Transport.
 * When `creds` is supplied (gateway mode) the request is processed inside an
 * AsyncLocalStorage context so tool handlers pick up the per-request key
 * without cross-tenant leakage. Never rethrows.
 */
async function handleMcpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  creds?: PmgCredentials,
): Promise<void> {
  const server = createFreshServer();
  const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    if (creds) {
      await transport.handleRequest(req, res);
    } else {
      await transport.handleRequest(req, res);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error("MCP request handling failed", { error: message });
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null }));
    }
  }
}

async function startStdioTransport(): Promise<void> {
  const server = createFreshServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Driversnote MCP server running on stdio");
}

/**
 * Start the server with HTTP Streamable transport.
 *
 * Refuses to listen unless CONDUIT_S2S_SECRET is a real secret. In gateway
 * mode the credentials are read from X-PMG-Username and X-PMG-Password on each
 * request and a request without both is rejected; there is no fallback to env.
 */
export async function startHttpTransport(): Promise<HttpServer> {
  const { secret: s2sSecret, insecureDev } = resolveS2sSecret();
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const host = resolveBindHost(s2sSecret);
  if (insecureDev) {
    // error level so LOG_LEVEL=warn|error cannot hide the bypass.
    logger.error(INSECURE_DEV_WARNING);
  }
  // SECURITY-REVIEW: auth mode selection. Anything other than env|gateway is refused.
  const authMode = (process.env.AUTH_MODE || "env").trim();
  if (authMode !== "env" && authMode !== "gateway") {
    refuseStart(`Refusing to start HTTP transport: AUTH_MODE must be "env" or "gateway" (got "${authMode}").`);
  }
  const isGatewayMode = authMode === "gateway";
  if (!isGatewayMode) {
    const credentials = getCredentials();
    if ("error" in credentials) {
      logger.warn(`AUTH_MODE=env but PMG credentials are not set: ${credentials.error}`);
    }
  }

  const httpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    // Shallow, unauthenticated liveness probe. Must NOT read credentials or call upstream.
    if (url.pathname === "/health" || url.pathname === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    if (url.pathname === "/mcp") {
      // SECURITY-REVIEW: X-Gateway-S2S check. Enforced before any Driversnote credential is read.
      // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1.
      if (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.",
          }),
        );
        return;
      }

      if (isGatewayMode) {
        // SECURITY-REVIEW: gateway credential path. Reject explicitly when missing; never fall through to env.
        const credentials = getCredentials(undefined, (name) => headerValue(req.headers[name]));
        if ("error" in credentials) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing credentials", message: credentials.error }));
          return;
        }
        void handleMcpRequest(req, res, credentials);
        return;
      }

      void handleMcpRequest(req, res);
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    httpServer.once("error", onError);
    httpServer.listen(port, host, () => {
      httpServer.off("error", onError);
      const addr = httpServer.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : port;
      logger.info(`Driversnote MCP server listening on http://${host}:${actualPort}/mcp`);
      logger.info(`Health check available at http://${host}:${actualPort}/health`);
      logger.info(
        `Authentication mode: ${isGatewayMode ? "gateway (X-PMG-Username and X-PMG-Password headers)" : "env (PMG_USERNAME and PMG_PASSWORD environment variables)"}`,
      );
      resolve();
    });
  });

  return httpServer;
}

/** Main entry point - select transport based on MCP_TRANSPORT env var. */
async function main() {
  const transportType = process.env.MCP_TRANSPORT || "stdio";

  // Fail fast on bad configuration (before accepting any request).
  const baseUrl = getBaseUrl(); // throws if PMG_BASE_URL is invalid
  const tiers = [...getEnabledTiers()]; // throws on an unknown tier name
  logger.info("Starting Driversnote MCP server", {
    transport: transportType,
    apiBaseUrl: baseUrl,
    enabledTiers: tiers,
    toolCount: listTools().length,
    logLevel: process.env.LOG_LEVEL || "info",
    nodeVersion: process.version,
  });

  if (transportType === "http") {
    const httpServer = await startHttpTransport();
    const shutdown = async () => {
      logger.info("Shutting down Driversnote MCP server...");
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    if (!getCredentials()) {
      const credentials = getCredentials();
      if ("error" in credentials) {
        logger.warn(`AUTH_MODE=env but PMG credentials are not set: ${credentials.error}`);
      }
    }
    await startStdioTransport();
  }
}

// Vitest imports this module. Skip the CLI entrypoint there.
if (process.env.VITEST !== "true") {
  main().catch((error) => {
    logger.error("Fatal startup error", { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  });
}
