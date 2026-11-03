import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Agent } from "undici";
import type { ApiResult, EndpointSpec, PmgCredentials } from "./types.js";

export const API_PREFIX = "/api2/json";
export const TICKET_PATH = "/api2/json/access/ticket";
export const TICKET_TTL_MS = 90 * 60 * 1000;
export const CSRF_HEADER = "CSRFPreventionToken";
export const AUTH_COOKIE = "PMGAuthCookie";

interface Ticket {
  ticket: string;
  csrf: string;
  username: string;
  expiresAt: number;
}

interface TicketResult {
  ok: boolean;
  ticket?: Ticket;
  error?: string;
}

// Tickets are cached per (baseUrl, username, password) so one gateway user's
// ticket is never used for another user. The key is a SHA-256 digest of the
// credential tuple so the plaintext password is never held as a Map key.
// The cache is an LRU (Map insertion order) capped at MAX_TICKET_CACHE entries.
export const MAX_TICKET_CACHE = 100;
export const UPSTREAM_TIMEOUT_MS = 30_000;
const ticketCache = new Map<string, Ticket>();

function cacheKey(creds: PmgCredentials): string {
  return createHash("sha256").update(JSON.stringify([creds.baseUrl, creds.username, creds.password])).digest("hex");
}

function sweepExpired(now = Date.now()): void {
  for (const [key, ticket] of ticketCache) {
    if (ticket.expiresAt <= now) ticketCache.delete(key);
  }
}

function cacheGet(key: string): Ticket | undefined {
  const ticket = ticketCache.get(key);
  if (!ticket) return undefined;
  if (Date.now() >= ticket.expiresAt) {
    ticketCache.delete(key);
    return undefined;
  }
  // Refresh recency.
  ticketCache.delete(key);
  ticketCache.set(key, ticket);
  return ticket;
}

function cacheSet(key: string, ticket: Ticket): void {
  sweepExpired();
  ticketCache.delete(key);
  ticketCache.set(key, ticket);
  while (ticketCache.size > MAX_TICKET_CACHE) {
    const oldest = ticketCache.keys().next().value;
    if (oldest === undefined) break;
    ticketCache.delete(oldest);
  }
}

export function clearTicketCache(): void {
  ticketCache.clear();
}

export function ticketCacheSize(): number {
  return ticketCache.size;
}

export function resolveBaseUrl(raw?: string): string {
  const value = (raw ?? "").trim();
  if (!value) throw new Error("PMG_BASE_URL is required (for example https://pmg.example.com:8006).");
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid PMG_BASE_URL: not a valid URL.");
  }
  if (url.username || url.password || url.hash) {
    throw new Error("Invalid PMG_BASE_URL: userinfo and fragments are not allowed.");
  }
  if (url.protocol === "https:") {
    if (!url.hostname) throw new Error("Invalid PMG_BASE_URL: hostname is required.");
    return value;
  }
  if (url.protocol === "http:") {
    const host = url.hostname.toLowerCase();
    if (host !== "127.0.0.1" && host !== "localhost") {
      throw new Error("Invalid PMG_BASE_URL: http is only allowed for localhost.");
    }
    return value;
  }
  throw new Error("Invalid PMG_BASE_URL: only https is allowed except http://127.0.0.1 and http://localhost.");
}

export function getBaseUrl(env: NodeJS.ProcessEnv = process.env): string {
  return resolveBaseUrl(env.PMG_BASE_URL);
}

export function getCredentials(
  env: NodeJS.ProcessEnv = process.env,
  getHeader?: (name: string) => string | undefined,
): PmgCredentials | { error: string } {
  let baseUrl: string;
  try {
    baseUrl = getBaseUrl(env);
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
  if (getHeader) {
    const username = (getHeader("x-pmg-username") ?? "").trim();
    const password = (getHeader("x-pmg-password") ?? "").trim();
    if (!username || !password) {
      return { error: "Missing X-PMG-Username or X-PMG-Password header (gateway mode requires both)." };
    }
    return { username, password, baseUrl };
  }
  const username = (env.PMG_USERNAME ?? "").trim();
  const password = (env.PMG_PASSWORD ?? "").trim();
  if (!username || !password) {
    return { error: "Missing PMG_USERNAME or PMG_PASSWORD." };
  }
  return { username, password, baseUrl };
}

function redactSecrets(text: string, secrets: string[]): string {
  return secrets.reduce((acc, secret) => (secret ? acc.split(secret).join("[REDACTED]") : acc), text);
}

function errorResult(kind: NonNullable<ApiResult["error"]>["kind"], message: string): ApiResult {
  return { ok: false, error: { kind, message } };
}

export async function getTicket(creds: PmgCredentials): Promise<TicketResult> {
  const key = cacheKey(creds);
  const cached = cacheGet(key);
  if (cached) {
    return { ok: true, ticket: cached };
  }

  let response: Response;
  try {
    response = await fetch(`${creds.baseUrl}${TICKET_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ username: creds.username, password: creds.password }).toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      dispatcher: getAgent() as never,
    } as RequestInit);
  } catch (error) {
    return { ok: false, error: networkMessage(error, [creds.username, creds.password]) };
  }

  if (response.status >= 300) {
    ticketCache.delete(key);
    const message = redactSecrets(`Unable to authenticate to PMG (status ${response.status}).`, [
      creds.username,
      creds.password,
    ]);
    return { ok: false, error: message };
  }

  let body: { data?: { ticket?: string; CSRFPreventionToken?: string; username?: string } };
  try {
    body = (await response.json()) as typeof body;
  } catch {
    ticketCache.delete(key);
    return { ok: false, error: "Invalid PMG ticket response: body is not valid JSON." };
  }
  const ticket = body?.data?.ticket;
  const csrf = body?.data?.CSRFPreventionToken;
  const username = body?.data?.username;
  if (!ticket || !csrf) {
    ticketCache.delete(key);
    return { ok: false, error: "Invalid PMG ticket response." };
  }

  const nextTicket: Ticket = {
    ticket,
    csrf,
    username: username ?? creds.username,
    expiresAt: Date.now() + TICKET_TTL_MS,
  };
  cacheSet(key, nextTicket);
  return { ok: true, ticket: nextTicket };
}

function networkMessage(error: unknown, secrets: string[]): string {
  const name = error instanceof Error ? error.name : "";
  if (name === "TimeoutError" || name === "AbortError") {
    return `PMG request timed out after ${UPSTREAM_TIMEOUT_MS / 1000}s.`;
  }
  const detail = error instanceof Error ? error.message : String(error);
  return redactSecrets(`PMG request failed: ${detail}`, secrets);
}

// One undici Agent per CA file path; the file is read once per path.
const agentCache = new Map<string, Agent>();

function getAgent(): Agent | undefined {
  const certPath = process.env.PMG_CA_CERT_FILE;
  if (!certPath) return undefined;
  let agent = agentCache.get(certPath);
  if (!agent) {
    agent = new Agent({ connect: { ca: readFileSync(certPath, "utf8") } });
    agentCache.set(certPath, agent);
  }
  return agent;
}

const STRICT_CIDR_RE = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

function pathParamNames(endpoint: EndpointSpec): string[] {
  return [...endpoint.path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
}

/**
 * Substitute `{param}` placeholders on the RAW path template, before any URL
 * is constructed (new URL() would percent-encode the braces and break the
 * match). Throws on a missing/unsafe value.
 */
export function buildPath(endpoint: EndpointSpec, args: Record<string, unknown>): string {
  return endpoint.path.replace(/\{([^}]+)\}/g, (_m, name: string) => {
    const raw = args[name];
    if (raw === undefined || raw === null) {
      throw new Error(`Missing required path parameter "${name}".`);
    }
    const value = String(raw);
    if (value.trim() === "" || value === "." || value === "..") {
      throw new Error(`Invalid value for path parameter "${name}": must not be empty, "." or "..".`);
    }
    // A "/" would add path segments. The only legitimate case is a CIDR
    // (e.g. mynetworks 192.168.0.0/24), which is sent percent-encoded.
    if (value.includes("/") && !(name === "cidr" && STRICT_CIDR_RE.test(value))) {
      throw new Error(`Invalid value for path parameter "${name}": must not contain "/".`);
    }
    return encodeURIComponent(value);
  });
}

export async function execute(
  endpoint: EndpointSpec,
  args: Record<string, unknown>,
  creds: PmgCredentials,
): Promise<ApiResult> {
  let path: string;
  try {
    path = buildPath(endpoint, args);
  } catch (error) {
    return errorResult("config", error instanceof Error ? error.message : String(error));
  }
  const pathParams = new Set(pathParamNames(endpoint));
  // Forward only declared, non-path params; undeclared arguments are dropped.
  const fields = new URLSearchParams();
  for (const [key, value] of Object.entries(args)) {
    if (pathParams.has(key) || !Object.hasOwn(endpoint.params, key)) continue;
    if (value === undefined || value === null) continue;
    fields.set(key, String(value));
  }
  const hasBody = endpoint.method === "POST" || endpoint.method === "PUT";
  const base = `${creds.baseUrl}${API_PREFIX}${path}`;
  const finalUrl = !hasBody && fields.size > 0 ? `${base}?${fields.toString()}` : base;
  const body = hasBody ? fields.toString() : undefined;

  // At most ONE re-auth retry per call.
  for (let attempt = 0; attempt < 2; attempt++) {
    const ticketResult = await getTicket(creds);
    if (!ticketResult.ok || !ticketResult.ticket) {
      return errorResult("auth", ticketResult.error ?? "Unable to authenticate to PMG.");
    }
    const ticket = ticketResult.ticket;
    const secrets = [creds.username, creds.password, ticket.ticket, ticket.csrf];
    const headers: Record<string, string> = {
      cookie: `${AUTH_COOKIE}=${ticket.ticket}`,
    };
    if (endpoint.method !== "GET") {
      headers[CSRF_HEADER] = ticket.csrf;
    }
    if (hasBody) headers["content-type"] = "application/x-www-form-urlencoded";

    let response: Response;
    try {
      response = await fetch(finalUrl, {
        method: endpoint.method,
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
        dispatcher: getAgent() as never,
      } as RequestInit);
    } catch (error) {
      return errorResult("network", networkMessage(error, secrets));
    }
    if (response.status === 401) {
      ticketCache.delete(cacheKey(creds));
      if (attempt === 0) continue;
      return errorResult("auth", "PMG rejected the request as unauthorized (401) after re-authenticating.");
    }
    if (response.status >= 300 && response.status < 400) {
      return errorResult("http", `PMG returned an unexpected redirect status ${response.status}.`);
    }
    const responseText = await response.text();
    let data: unknown;
    try {
      data = JSON.parse(responseText);
    } catch {
      data = { message: redactSecrets(responseText, secrets) };
    }
    if (!response.ok) {
      const message = redactSecrets(
        typeof data === "object" && data !== null && "message" in data
          ? String((data as { message?: unknown }).message)
          : JSON.stringify(data ?? {}),
        secrets,
      );
      return errorResult("upstream", message);
    }
    return { ok: true, data };
  }
  return errorResult("auth", "Unable to authenticate to PMG.");
}
