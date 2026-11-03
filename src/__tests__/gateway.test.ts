import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request } from "node:http";
import { createHmac } from "node:crypto";
import type { Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { startHttpTransport } from "../index.js";
import { clearTicketCache } from "../utils/client.js";

const ENV_KEYS = [
  "MCP_HTTP_PORT", "MCP_HTTP_HOST", "AUTH_MODE", "CONDUIT_S2S_SECRET", "PMG_USERNAME", "PMG_PASSWORD", "PMG_BASE_URL",
];
const saved: Record<string, string | undefined> = {};
let server: HttpServer | undefined;

function post(port: number, headers: Record<string, string>, body: unknown): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers } },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

const SECRET = "fake-test-secret-value-0123456789-abcdef";
function sign(): string {
  const t = Math.floor(Date.now() / 1000);
  return `t=${t},v1=${createHmac("sha256", SECRET).update(`t=${t}`).digest("hex")}`;
}

const callVersion = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "pmg_version_get", arguments: {} } };

function mockFetch() {
  const calls: { url: string; body?: string; headers: Record<string, string> }[] = [];
  vi.stubGlobal("fetch", async (url: string, init: { body?: string; headers?: Record<string, string> }) => {
    calls.push({ url: String(url), body: init?.body, headers: init?.headers ?? {} });
    const data = String(url).endsWith("/access/ticket")
      ? { data: { ticket: "fake-ticket", CSRFPreventionToken: "fake-csrf", username: "x" } }
      : { data: { version: "4.0.0" } };
    return new Response(JSON.stringify(data), { status: 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

async function boot(env: Record<string, string>): Promise<number> {
  Object.assign(process.env, { MCP_HTTP_PORT: "0", MCP_HTTP_HOST: "127.0.0.1", CONDUIT_S2S_SECRET: SECRET, PMG_BASE_URL: "https://pmg.example.com:8006", ...env });
  server = await startHttpTransport();
  return (server.address() as AddressInfo).port;
}

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  clearTicketCache();
});

afterEach(async () => {
  vi.unstubAllGlobals();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

describe("gateway mode credentials", () => {
  it("uses header credentials (mixed-case names), never env credentials", async () => {
    const calls = mockFetch();
    const port = await boot({ AUTH_MODE: "gateway", PMG_USERNAME: "env-user@pmg", PMG_PASSWORD: "env-fake-password" });
    const res = await post(port, { "X-Gateway-S2S": sign(), "X-PMG-Username": "hdr-user@pmg", "X-PMG-Password": "hdr-fake-password" }, callVersion);
    expect(res.status).toBe(200);
    expect(res.text).toContain("4.0.0");
    const ticketCall = calls.find((c) => c.url.endsWith("/access/ticket"));
    expect(ticketCall).toBeDefined();
    const form = new URLSearchParams(ticketCall?.body);
    expect(form.get("username")).toBe("hdr-user@pmg");
    expect(form.get("password")).toBe("hdr-fake-password");
    expect(calls.map((c) => c.body ?? "").join("")).not.toContain("env-");
  });

  it("rejects a request without gateway headers instead of falling back to env", async () => {
    const calls = mockFetch();
    const port = await boot({ AUTH_MODE: "gateway", PMG_USERNAME: "env-user@pmg", PMG_PASSWORD: "env-fake-password" });
    const res = await post(port, { "x-gateway-s2s": sign() }, callVersion);
    expect(res.status).toBe(401);
    expect(calls).toHaveLength(0);
  });

  it("does not share tickets between different gateway users", async () => {
    const calls = mockFetch();
    const port = await boot({ AUTH_MODE: "gateway" });
    const base = { "x-gateway-s2s": sign() };
    await post(port, { ...base, "x-pmg-username": "a@pmg", "x-pmg-password": "fake-a" }, callVersion);
    await post(port, { ...base, "x-pmg-username": "b@pmg", "x-pmg-password": "fake-b" }, callVersion);
    const logins = calls.filter((c) => c.url.endsWith("/access/ticket")).map((c) => new URLSearchParams(c.body).get("username"));
    expect(logins).toEqual(["a@pmg", "b@pmg"]);
  });

  it("env mode still uses env credentials", async () => {
    const calls = mockFetch();
    const port = await boot({ AUTH_MODE: "env", PMG_USERNAME: "env-user@pmg", PMG_PASSWORD: "env-fake-password" });
    await post(port, { "x-gateway-s2s": sign() }, callVersion);
    const t = calls.find((c) => c.url.endsWith("/access/ticket"));
    expect(new URLSearchParams(t?.body).get("username")).toBe("env-user@pmg");
  });
});
