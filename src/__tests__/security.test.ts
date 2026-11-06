import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request } from "node:http";
import { createHmac } from "node:crypto";
import type { Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { isLoopbackBindHost, resolveS2sSecret, startHttpTransport } from "../index.js";
import { buildPath, clearTicketCache, execute, getTicket, MAX_TICKET_CACHE, ticketCacheSize } from "../utils/client.js";
import { ENDPOINTS } from "../endpoints.js";
import { getEnabledTiers } from "../tiers.js";
import type { PmgCredentials } from "../utils/types.js";

const GOOD_SECRET = "fake-test-secret-value-0123456789-abcdef";
const creds: PmgCredentials = { username: "u@pmg", password: "fake-password", baseUrl: "https://pmg.example.com:8006" };

function endpoint(tool: string) {
  const e = ENDPOINTS.find((x) => x.tool === tool);
  if (!e) throw new Error(`no endpoint ${tool}`);
  return e;
}

function ticketOrData(data: unknown, status = 200, log?: { url: string; init: RequestInit }[]) {
  return vi.fn(async (input: string, init: RequestInit) => {
    log?.push({ url: String(input), init });
    if (String(input).endsWith("/access/ticket")) {
      return new Response(JSON.stringify({ data: { ticket: "fake-ticket", CSRFPreventionToken: "fake-csrf", username: "u@pmg" } }), { status: 200 });
    }
    return new Response(JSON.stringify(data), { status });
  });
}

beforeEach(() => {
  clearTicketCache();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("S2S secret resolution", () => {
  function expectRefusal(env: NodeJS.ProcessEnv, pattern: RegExp) {
    const exit = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("exit");
    }) as never);
    expect(() => resolveS2sSecret(env)).toThrow("exit");
    expect(exit).toHaveBeenCalledWith(1);
    return pattern;
  }

  it("accepts a >= 32 char secret", () => {
    expect(resolveS2sSecret({ CONDUIT_S2S_SECRET: GOOD_SECRET })).toEqual({ secret: GOOD_SECRET, insecureDev: false });
  });

  it.each(["short-secret", "a".repeat(31)])("rejects a secret under 32 chars (%s)", (value) => {
    expectRefusal({ CONDUIT_S2S_SECRET: value }, /32/);
  });

  it.each(["changeme", "Secret", "placeholder", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "your-secret-goes-here-and-is-long-enough", "CHANGE-ME"])(
    "rejects placeholder %s even with insecure dev flag",
    (value) => {
      expectRefusal({ CONDUIT_S2S_SECRET: value, MCP_ALLOW_INSECURE_DEV: "1" }, /placeholder/);
    },
  );

  it("never prints the secret", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const out = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const errw = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const outw = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    expectRefusal({ CONDUIT_S2S_SECRET: "hunter2-fake" }, /32/);
    const printed = [err, out, errw, outw].flatMap((s) => s.mock.calls.flat().map(String)).join("");
    expect(printed).not.toContain("hunter2-fake");
  });

  it("empty secret requires the insecure-dev flag", () => {
    expect(resolveS2sSecret({ MCP_ALLOW_INSECURE_DEV: "1" })).toEqual({ secret: "", insecureDev: true });
    expectRefusal({}, /empty/);
  });
});

describe("isLoopbackBindHost", () => {
  it.each(["127.0.0.1", "127.5.5.5", "localhost", "::1", "[::1]", "::ffff:127.0.0.1"])("%s is loopback", (h) => {
    expect(isLoopbackBindHost(h)).toBe(true);
  });
  it.each(["0.0.0.0", "10.0.0.1", "example.com", "128.0.0.1"])("%s is not loopback", (h) => {
    expect(isLoopbackBindHost(h)).toBe(false);
  });
});

describe("HTTP host check and body limit", () => {
  const keys = ["MCP_HTTP_PORT", "MCP_HTTP_HOST", "AUTH_MODE", "CONDUIT_S2S_SECRET", "PMG_BASE_URL", "MCP_ALLOWED_HOSTS", "MCP_ALLOW_INSECURE_DEV"];
  const saved: Record<string, string | undefined> = {};
  let server: HttpServer | undefined;
  beforeEach(() => {
    for (const k of keys) saved[k] = process.env[k];
    for (const k of keys) delete process.env[k];
  });
  afterEach(async () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    server = undefined;
  });

  async function boot(env: Record<string, string>): Promise<number> {
    Object.assign(process.env, { MCP_HTTP_PORT: "0", MCP_HTTP_HOST: "127.0.0.1", CONDUIT_S2S_SECRET: GOOD_SECRET, AUTH_MODE: "gateway", PMG_BASE_URL: "https://pmg.example.com:8006", ...env });
    server = await startHttpTransport();
    return (server.address() as AddressInfo).port;
  }

  function send(port: number, opts: { host?: string; path?: string; headers?: Record<string, string>; body?: string; method?: string }): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream", ...opts.headers };
      if (opts.host !== undefined) headers.host = opts.host;
      const req = request({ host: "127.0.0.1", port, path: opts.path ?? "/mcp", method: opts.method ?? "POST", headers }, (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      });
      req.on("error", reject);
      req.end(opts.body ?? "{}");
    });
  }

  function sign(): string {
    const t = Math.floor(Date.now() / 1000);
    return `t=${t},v1=${createHmac("sha256", GOOD_SECRET).update(`t=${t}`).digest("hex")}`;
  }

  it("rejects a foreign Host with 403 on loopback bind (default allow list)", async () => {
    const port = await boot({});
    expect((await send(port, { host: "evil.example.com" })).status).toBe(403);
    expect((await send(port, { host: "evil.example.com:8080" })).status).toBe(403);
    expect((await send(port, { host: "evil.example.com", path: "/health", method: "GET" })).status).toBe(200); // liveness probe is Host-agnostic
  });

  it("accepts localhost / 127.0.0.1 hosts with a port (reaches auth, 401 without S2S)", async () => {
    const port = await boot({});
    expect((await send(port, { host: `localhost:${port}` })).status).toBe(401);
    expect((await send(port, { host: `127.0.0.1:${port}` })).status).toBe(401);
  });

  it("honors MCP_ALLOWED_HOSTS and rejects malformed or out-of-range authorities", async () => {
    const port = await boot({ MCP_ALLOWED_HOSTS: "Gateway.Internal" });
    expect((await send(port, { host: "gateway.internal" })).status).toBe(401);
    expect((await send(port, { host: "gateway.internal:99999" })).status).toBe(403);
    expect((await send(port, { host: "gateway.internal.evil.com" })).status).toBe(403);
    expect((await send(port, { host: "gateway.internal/x" })).status).toBe(403);
  });

  it("does not check Host on a non-loopback bind without MCP_ALLOWED_HOSTS", async () => {
    const port = await boot({ MCP_HTTP_HOST: "0.0.0.0" });
    expect((await send(port, { host: "anything.example.com" })).status).toBe(401);
  });

  it("checks Host on a non-loopback bind once MCP_ALLOWED_HOSTS is set", async () => {
    const port = await boot({ MCP_HTTP_HOST: "0.0.0.0", MCP_ALLOWED_HOSTS: "gw.example.com" });
    expect((await send(port, { host: "anything.example.com" })).status).toBe(403);
    expect((await send(port, { host: "gw.example.com" })).status).toBe(401);
  });

  it("warns about MCP_ALLOWED_HOSTS entries with a port", async () => {
    const warn = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const logw = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    await boot({ MCP_ALLOWED_HOSTS: "gw.example.com:8080,::1" });
    const printed = [warn, log, logw].flatMap((s) => s.mock.calls.flat().map(String)).join("");
    expect(printed).toContain("gw.example.com:8080");
    expect(printed).toContain("will never match");
  });

  it("returns 413 for a Content-Length over 1 MiB", async () => {
    const port = await boot({});
    const res = await send(port, { headers: { "x-gateway-s2s": sign(), "x-pmg-username": "u@pmg", "x-pmg-password": "fake" }, body: "x".repeat(1024 * 1024 + 1) });
    expect(res.status).toBe(413);
  });

  it("returns 413 for an oversized chunked body", async () => {
    const port = await boot({});
    const status = await new Promise<number>((resolve, reject) => {
      const req = request(
        { host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { "content-type": "application/json", "transfer-encoding": "chunked", "x-gateway-s2s": sign(), "x-pmg-username": "u@pmg", "x-pmg-password": "fake" } },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on("error", (e) => (String(e).includes("ECONNRESET") || String(e).includes("EPIPE") ? undefined : reject(e)));
      req.write("x".repeat(600 * 1024));
      req.write("x".repeat(600 * 1024));
      req.end();
    });
    expect(status).toBe(413);
  });

  it("returns 400 for invalid JSON under the limit", async () => {
    const port = await boot({});
    const res = await send(port, { headers: { "x-gateway-s2s": sign(), "x-pmg-username": "u@pmg", "x-pmg-password": "fake" }, body: "{not json" });
    expect(res.status).toBe(400);
  });
});

describe("path parameter substitution", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    ["pmg_domain_get", { domain: "example.com" }, "/api2/json/config/domains/example.com"],
    ["pmg_domain_get", { domain: "a b&c" }, "/api2/json/config/domains/a%20b%26c"],
    ["pmg_mynetwork_get", { cidr: "10.0.0.0/8" }, "/api2/json/config/mynetworks/10.0.0.0%2F8"],
    ["pmg_postfix_queue_message_get", { node: "pmg1", queue: "deferred", queue_id: "ABC123" }, "/api2/json/nodes/pmg1/postfix/queue/deferred/ABC123"],
    ["pmg_node_tracker_message_get", { node: "pmg1", id: "x?y" }, "/api2/json/nodes/pmg1/tracker/x%3Fy"],
  ];

  it.each(cases)("%s %j end to end", async (tool, args, path) => {
    const log: { url: string; init: RequestInit }[] = [];
    vi.stubGlobal("fetch", ticketOrData({ data: [] }, 200, log));
    const e = ENDPOINTS.find((x) => x.tool === tool);
    if (!e) throw new Error(`missing ${tool}`);
    const res = await execute(e, args, creds);
    expect(res.ok).toBe(true);
    const url = new URL(log.at(-1)?.url ?? "");
    expect(url.pathname).toBe(path);
    expect(log.at(-1)?.url).not.toMatch(/%7B|\{/i);
  });

  it("covers every path-param endpoint without leaving placeholders", async () => {
    const withParams = ENDPOINTS.filter((e) => e.path.includes("{"));
    expect(withParams.length).toBeGreaterThan(10);
    for (const e of withParams) {
      const names = [...e.path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      for (const n of names) expect(Object.keys(e.params), `${e.tool} declares ${n}`).toContain(n);
      const args = Object.fromEntries(names.map((n) => [n, n === "cidr" ? "10.0.0.0/8" : "v1"]));
      expect(buildPath(e, args)).not.toMatch(/[{}]/);
    }
  });

  it.each(["", "   ", ".", "..", "a/b", "../x"])("rejects unsafe value %j with no upstream call", async (value) => {
    const fetchMock = ticketOrData({});
    vi.stubGlobal("fetch", fetchMock);
    const res = await execute(endpoint("pmg_domain_get"), { domain: value }, creds);
    expect(res.ok).toBe(false);
    expect(res.error?.message).toMatch(/path parameter "domain"/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a non-CIDR value containing a slash for cidr and a missing param", async () => {
    vi.stubGlobal("fetch", ticketOrData({}));
    expect((await execute(endpoint("pmg_mynetwork_get"), { cidr: "../etc" }, creds)).ok).toBe(false);
    const missing = await execute(endpoint("pmg_domain_get"), {}, creds);
    expect(missing.ok).toBe(false);
    expect(missing.error?.message).toMatch(/Missing required path parameter/);
  });
});

describe("401 re-auth retry", () => {
  it("retries exactly once on a persistent 401", async () => {
    const log: { url: string; init: RequestInit }[] = [];
    vi.stubGlobal("fetch", ticketOrData({ message: "no" }, 401, log));
    const res = await execute(endpoint("pmg_version_get"), {}, creds);
    expect(res.ok).toBe(false);
    expect(res.error?.kind).toBe("auth");
    const upstream = log.filter((c) => !c.url.endsWith("/access/ticket"));
    const tickets = log.filter((c) => c.url.endsWith("/access/ticket"));
    expect(upstream).toHaveLength(2);
    expect(tickets).toHaveLength(2);
  });

  it("succeeds when the second attempt works", async () => {
    let n = 0;
    const log: { url: string; init: RequestInit }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string, init: RequestInit) => {
      log.push({ url: String(input), init });
      if (String(input).endsWith("/access/ticket")) {
        return new Response(JSON.stringify({ data: { ticket: `t${log.length}`, CSRFPreventionToken: "c", username: "u" } }), { status: 200 });
      }
      return n++ === 0 ? new Response("{}", { status: 401 }) : new Response(JSON.stringify({ data: 1 }), { status: 200 });
    }));
    const res = await execute(endpoint("pmg_version_get"), {}, creds);
    expect(res.ok).toBe(true);
    expect(log.filter((c) => !c.url.endsWith("/access/ticket"))).toHaveLength(2);
  });
});

describe("ticket cache", () => {
  function ticketFetch() {
    const f = vi.fn(async () => new Response(JSON.stringify({ data: { ticket: "t", CSRFPreventionToken: "c", username: "u" } }), { status: 200 }));
    vi.stubGlobal("fetch", f);
    return f;
  }

  it("does not use the plaintext password as a cache key (sha256 digest)", async () => {
    ticketFetch();
    const spy = vi.spyOn(Map.prototype, "set");
    await getTicket({ ...creds, password: "plaintext-fake-pass" });
    const keys = spy.mock.calls.map((c) => String(c[0]));
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k).not.toContain("plaintext-fake-pass");
    }
    expect(keys.some((k) => /^[0-9a-f]{64}$/.test(k))).toBe(true);
  });

  it("caps the cache size with LRU eviction", async () => {
    const f = ticketFetch();
    for (let i = 0; i < MAX_TICKET_CACHE + 20; i++) await getTicket({ ...creds, username: `user${i}` });
    expect(ticketCacheSize()).toBe(MAX_TICKET_CACHE);
    f.mockClear();
    await getTicket({ ...creds, username: `user${MAX_TICKET_CACHE + 19}` }); // newest still cached
    expect(f).not.toHaveBeenCalled();
    await getTicket({ ...creds, username: "user0" }); // oldest evicted
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("evicts expired entries on insert", async () => {
    vi.useFakeTimers();
    try {
      ticketFetch();
      for (let i = 0; i < 5; i++) await getTicket({ ...creds, username: `old${i}` });
      expect(ticketCacheSize()).toBe(5);
      vi.advanceTimersByTime(91 * 60 * 1000);
      await getTicket({ ...creds, username: "fresh" });
      expect(ticketCacheSize()).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("returns a clear error when the ticket response is not JSON", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>nope</html>", { status: 200 })));
    const r = await getTicket(creds);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not valid JSON/);
  });
});

describe("only declared params are forwarded", () => {
  it("drops undeclared args from query and body", async () => {
    const log: { url: string; init: RequestInit }[] = [];
    vi.stubGlobal("fetch", ticketOrData({ data: {} }, 200, log));
    const get = ENDPOINTS.find((e) => e.method === "GET" && Object.keys(e.params).some((k) => !e.path.includes(`{${k}}`)));
    if (!get) throw new Error("no GET endpoint with query params");
    const declared = Object.keys(get.params).find((k) => !get.path.includes(`{${k}}`)) as string;
    const args: Record<string, unknown> = { evil: "1", __proto__x: "2" };
    for (const k of Object.keys(get.params)) args[k] = k === declared ? "5" : "v";
    await execute(get, args, creds);
    const q = new URL(log.at(-1)?.url ?? "").searchParams;
    expect(q.has("evil")).toBe(false);
    expect(q.get(declared)).toBe("5");

    log.length = 0;
    await execute(endpoint("pmg_domain_create"), { domain: "example.com", comment: "c", evil: "1" }, creds);
    expect(log.at(-1)?.init.body).toBe("domain=example.com&comment=c");
  });
});

describe("tier env", () => {
  it("ignores foreign tier env vars from copy-pasted sources", () => {
    const foreign = `${"DRIVERS"}NOTE_TOOL_TIERS`;
    expect(getEnabledTiers({ [foreign]: "admin" } as never)).toEqual(["read"]);
    expect(getEnabledTiers({ PMG_TOOL_TIERS: "read,write" } as never)).toEqual(["read", "write"]);
  });
});
