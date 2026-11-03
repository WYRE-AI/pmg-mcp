import { readFileSync } from "node:fs";
import { Agent } from "undici";
import type { ApiResult, EndpointSpec, PmgCredentials } from "./types.js";

export const DEFAULT_BASE_URL = "https://pmg.example.com:8006";
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

let ticketCache: Ticket | null = null;

export function clearTicketCache(): void {
  ticketCache = null;
}

export function resolveBaseUrl(raw?: string): string {
  const value = (raw ?? "").trim();
  if (!value) return DEFAULT_BASE_URL;
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
  const baseUrl = getBaseUrl(env);
  if (getHeader) {
    const username = (getHeader("X-PMG-Username") ?? "").trim();
    const password = (getHeader("X-PMG-Password") ?? "").trim();
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
  const cached = ticketCache;
  if (cached && Date.now() < cached.expiresAt) {
    return { ok: true, ticket: cached };
  }

  const response = await fetch(`${creds.baseUrl}${TICKET_PATH}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ username: creds.username, password: creds.password }).toString(),
    redirect: "manual",
  });

  if (response.status >= 400) {
    ticketCache = null;
    const message = redactSecrets(`Unable to authenticate to PMG (status ${response.status}).`, [
      creds.username,
      creds.password,
    ]);
    return { ok: false, error: message };
  }

  const body = (await response.json()) as {
    data?: { ticket?: string; CSRFPreventionToken?: string; username?: string };
  };
  const ticket = body.data?.ticket;
  const csrf = body.data?.CSRFPreventionToken;
  const username = body.data?.username;
  if (!ticket || !csrf) {
    ticketCache = null;
    return { ok: false, error: "Invalid PMG ticket response." };
  }

  const nextTicket: Ticket = {
    ticket,
    csrf,
    username: username ?? creds.username,
    expiresAt: Date.now() + TICKET_TTL_MS,
  };
  ticketCache = nextTicket;
  return { ok: true, ticket: nextTicket };
}

function getAgent(): Agent | undefined {
  const certPath = process.env.PMG_CA_CERT_FILE;
  if (!certPath) return undefined;
  const ca = readFileSync(certPath, "utf8");
  return new Agent({ connect: { ca } });
}

function requiredPathParams(endpoint: EndpointSpec, args: Record<string, unknown>): string[] {
  const names = Object.keys(endpoint.params).filter((key) => endpoint.path.includes(`{${key}}`));
  return names.filter((key) => args[key] !== undefined && args[key] !== null);
}

function buildUrl(endpoint: EndpointSpec, args: Record<string, unknown>, creds: PmgCredentials): URL {
  const url = new URL(`${creds.baseUrl}${API_PREFIX}${endpoint.path}`);
  for (const key of Object.keys(endpoint.params)) {
    if (!endpoint.path.includes(`{${key}}`)) continue;
    const value = args[key];
    if (value === undefined || value === null) continue;
    url.pathname = url.pathname.replace(`{${key}}`, encodeURIComponent(String(value)));
  }
  return url;
}

export async function execute(
  endpoint: EndpointSpec,
  args: Record<string, unknown>,
  creds: PmgCredentials,
): Promise<ApiResult> {
  const ticketResult = await getTicket(creds);
  if (!ticketResult.ok || !ticketResult.ticket) {
    return errorResult("auth", ticketResult.error ?? "Unable to authenticate to PMG.");
  }
  const ticket = ticketResult.ticket;

  const url = buildUrl(endpoint, args, creds);
  const pathParams = new Set(requiredPathParams(endpoint, args));
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(args)) {
    if (pathParams.has(key) || value === undefined || value === null) continue;
    if (endpoint.method === "GET" || endpoint.method === "DELETE") {
      query.set(key, String(value));
    }
  }
  const finalUrl = query.size > 0 ? `${url.toString()}${url.search ? "&" : "?"}${query.toString()}` : url.toString();

  const secrets = [creds.username, creds.password, ticket.ticket, ticket.csrf];
  const headers: Record<string, string> = {
    cookie: `${AUTH_COOKIE}=${ticket.ticket}`,
  };
  if (endpoint.method !== "GET") {
    headers[CSRF_HEADER] = ticket.csrf;
  }
  let body: string | undefined;
  if (endpoint.method === "POST" || endpoint.method === "PUT") {
    const form = new URLSearchParams();
    for (const [key, value] of Object.entries(args)) {
      if (pathParams.has(key) || value === undefined || value === null) continue;
      form.set(key, String(value));
    }
    body = form.toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  }

  const retryState: { retried: boolean } = { retried: false };
  while (true) {
    const response = await fetch(finalUrl, {
      method: endpoint.method,
      headers,
      body,
      redirect: "manual",
      dispatcher: getAgent() as never,
    });
    if (response.status === 401 && !retryState.retried) {
      retryState.retried = true;
      ticketCache = null;
      return execute(endpoint, args, creds);
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
}
