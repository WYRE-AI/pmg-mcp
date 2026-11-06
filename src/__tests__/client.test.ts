import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearTicketCache, execute, getBaseUrl, getCredentials, getTicket, resolveBaseUrl } from "../utils/client.js";
import { ENDPOINTS } from "../endpoints.js";
import type { PmgCredentials } from "../utils/types.js";

const credentials: PmgCredentials = {
  username: "mcp@pmg",
  password: "super-secret-password",
  baseUrl: "https://pmg.example.com:8006",
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

beforeEach(() => {
  clearTicketCache();
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("PMG base URL safety", () => {
  it("allows HTTPS and loopback HTTP", () => {
    expect(resolveBaseUrl("https://pmg.example.com:8006")).toBe("https://pmg.example.com:8006");
    expect(resolveBaseUrl("http://127.0.0.1:8006")).toBe("http://127.0.0.1:8006");
  });

  it.each([
    "http://pmg.example.com:8006",
    "https://user:secret@pmg.example.com:8006",
    "file:///etc/passwd",
    "not-a-url",
  ])("rejects unsafe PMG_BASE_URL %s", (value) => {
    expect(() => resolveBaseUrl(value)).toThrow(/PMG_BASE_URL/);
  });

  it("has no default base URL: unset or blank PMG_BASE_URL throws", () => {
    expect(() => resolveBaseUrl(undefined)).toThrow(/PMG_BASE_URL is required/);
    expect(() => resolveBaseUrl("   ")).toThrow(/PMG_BASE_URL is required/);
    expect(() => getBaseUrl({})).toThrow(/PMG_BASE_URL is required/);
  });

  it("getCredentials returns an error (never a default URL) when PMG_BASE_URL is unset", () => {
    const env = getCredentials({ PMG_USERNAME: "u@pmg", PMG_PASSWORD: "fake-password" });
    expect(env).toEqual({ error: expect.stringMatching(/PMG_BASE_URL is required/) });
    const gw = getCredentials({}, (name) => ({ "x-pmg-username": "u@pmg", "x-pmg-password": "fake-password" })[name]);
    expect(gw).toEqual({ error: expect.stringMatching(/PMG_BASE_URL is required/) });
  });

  it("reads the configured base URL", () => {
    expect(getBaseUrl({ PMG_BASE_URL: "https://pmg.example.com:8006" })).toBe("https://pmg.example.com:8006");
  });
});

describe("PMG ticket auth", () => {
  it("logs in with form-encoded credentials and caches the ticket", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({
      data: { ticket: "ticket-123", CSRFPreventionToken: "csrf-123", username: "mcp@pmg" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await getTicket(credentials);
    expect(result.ok).toBe(true);
    if (!result.ok || !result.ticket) throw new Error("ticket missing");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://pmg.example.com:8006/api2/json/access/ticket");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({ "content-type": "application/x-www-form-urlencoded" });
    expect(init.body).toBe("username=mcp%40pmg&password=super-secret-password");
    expect(init.redirect).toBe("manual");
  });

  it("reuses the cached ticket before expiry", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({
      data: { ticket: "ticket-123", CSRFPreventionToken: "csrf-123", username: "mcp@pmg" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await getTicket(credentials);
    await getTicket(credentials);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refreshes the ticket after 90 minutes", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(async () => jsonResponse({
      data: { ticket: "ticket-123", CSRFPreventionToken: "csrf-123", username: "mcp@pmg" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await getTicket(credentials);
    vi.advanceTimersByTime(91 * 60 * 1000);
    await getTicket(credentials);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("PMG API execution", () => {
  it("redacts credentials from authentication errors", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: "invalid credentials" }, 401));
    vi.stubGlobal("fetch", fetchMock);

    const result = await execute(
      ENDPOINTS.find((endpoint) => endpoint.tool === "pmg_version_get") as never,
      {},
      credentials,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error?.message).not.toContain("super-secret-password");
  });

  it("performs a mocked read call end to end", async () => {
    const fetchMock = vi.fn(async (input: string) =>
      new URL(input).pathname === "/api2/json/access/ticket"
        ? jsonResponse({
            data: { ticket: "ticket-123", CSRFPreventionToken: "csrf-123", username: "mcp@pmg" },
          })
        : jsonResponse({ data: { version: "4.0.0" } }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const endpoint = ENDPOINTS.find((item) => item.tool === "pmg_version_get");
    if (!endpoint) throw new Error("version endpoint missing");
    const result = await execute(endpoint, {}, credentials);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data).toEqual({ data: { version: "4.0.0" } });

    const [url, init] = fetchMock.mock.calls.at(-1) as unknown as [string, RequestInit];
    expect(String(url)).toBe("https://pmg.example.com:8006/api2/json/version");
    expect(init.method).toBe("GET");
    expect(init.headers).toMatchObject({ cookie: "PMGAuthCookie=ticket-123" });
    expect(init.headers).not.toHaveProperty("CSRFPreventionToken");
  });

  it("sends a CSRF token and form-encoded body on POST", async () => {
    const fetchMock = vi.fn(async (input: string) =>
      new URL(input).pathname === "/api2/json/access/ticket"
        ? jsonResponse({
            data: { ticket: "ticket-123", CSRFPreventionToken: "csrf-123", username: "mcp@pmg" },
          })
        : jsonResponse({ data: { ok: true } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await getTicket(credentials);

    const endpoint = ENDPOINTS.find((item) => item.tool === "pmg_domain_create");
    if (!endpoint) throw new Error("domain endpoint missing");
    const result = await execute(endpoint, { domain: "example.com", comment: "test" }, credentials);
    expect(result.ok).toBe(true);

    const [url, init] = fetchMock.mock.calls.at(-1) as unknown as [string, RequestInit];
    expect(String(url)).toBe("https://pmg.example.com:8006/api2/json/config/domains");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({ "content-type": "application/x-www-form-urlencoded" });
    expect(init.headers).toMatchObject({ "CSRFPreventionToken": "csrf-123" });
    expect(init.body).toBe("domain=example.com&comment=test");
  });
});

describe("credential resolution", () => {
  it("uses gateway headers only in gateway mode", () => {
    expect(getCredentials({ PMG_BASE_URL: "https://pmg.example.com:8006", AUTH_MODE: "gateway" }, () => undefined)).toEqual({
      error: "Missing X-PMG-Username or X-PMG-Password header (gateway mode requires both).",
    });
  });
});
