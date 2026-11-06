#!/usr/bin/env node
import { createServer, request as httpRequest } from "node:http";
import { createHmac } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function check(condition, message) {
  if (condition) {
    console.log(`  ok   ${message}`);
  } else {
    console.log(`  FAIL ${message}`);
    failures.push(message);
  }
}

const ticketResponse = {
  data: { ticket: "mock-ticket", CSRFPreventionToken: "mock-csrf", username: "mcp@pmg.example.com" },
};

const ticketLogins = [];
const mock = createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    res.setHeader("Content-Type", "application/json");
    if (req.method === "POST" && req.url === "/api2/json/access/ticket") {
      ticketLogins.push(new URLSearchParams(body).get("username"));
      res.writeHead(200);
      res.end(JSON.stringify(ticketResponse));
      return;
    }
    if (req.method === "GET" && req.url === "/api2/json/version") {
      res.writeHead(200);
      res.end(JSON.stringify({ data: { version: "4.0.0" } }));
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({ error: "not found" }));
  });
});

await new Promise((resolve) => mock.listen(0, "127.0.0.1", resolve));
const mockUrl = `http://127.0.0.1:${mock.address().port}`;

async function withServer(extraEnv, run) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(root, "dist/index.js")],
    env: { ...getDefaultEnvironment(), PMG_BASE_URL: mockUrl, PMG_USERNAME: "mcp@pmg.example.com", PMG_PASSWORD: "mock-password", AUTH_MODE: "env", MCP_TRANSPORT: "stdio", LOG_LEVEL: "warn", ...extraEnv },
    stderr: "pipe",
  });
  const client = new Client({ name: "pmg-smoke", version: "0.0.0" });
  await client.connect(transport);
  try {
    return await run(client);
  } finally {
    await client.close();
  }
}

function textOf(result) {
  return result.content.map((content) => content.text ?? "").join("");
}

try {
  console.log("\n[1] tools/list tier counts");
  await withServer({ PMG_TOOL_TIERS: "read,write,admin" }, async (client) => {
    const { tools } = await client.listTools();
    console.log(`  tools listed: ${tools.length}`);
    check(tools.length === 88, "88 tools are listed");
    check(new Set(tools.map((tool) => tool.name)).size === 88, "tool names are unique");
  });

  console.log("\n[2] mocked read call");
  await withServer({}, async (client) => {
    const result = await client.callTool({ name: "pmg_version_get", arguments: {} });
    const text = textOf(result);
    console.log(`  pmg_version_get -> ${text}`);
    check(result.isError !== true, "pmg_version_get succeeds");
    check(text.includes("4.0.0"), "mocked PMG response is returned");
  });

  console.log("\n[3] HTTP gateway mode: header credentials reach the upstream");
  const s2sSecret = "fake-smoke-s2s-secret-0123456789-abcdef";
  const child = spawn(process.execPath, [resolve(root, "dist/index.js")], {
    env: {
      ...getDefaultEnvironment(), PMG_BASE_URL: mockUrl, MCP_TRANSPORT: "http", AUTH_MODE: "gateway",
      MCP_HTTP_PORT: "0", MCP_HTTP_HOST: "127.0.0.1", CONDUIT_S2S_SECRET: s2sSecret, LOG_LEVEL: "info",
      PMG_USERNAME: "env-user@pmg", PMG_PASSWORD: "env-fake-password",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  try {
    const port = await new Promise((res, rej) => {
      let buf = "";
      const timer = setTimeout(() => rej(new Error("http server did not start")), 15000);
      child.stderr.on("data", (d) => {
        buf += d;
        const m = /listening on http:\/\/127\.0\.0\.1:(\d+)\/mcp/.exec(buf);
        if (m) { clearTimeout(timer); res(Number(m[1])); }
      });
      child.on("exit", () => rej(new Error("http server exited early")));
    });
    const post = (headers) => new Promise((res, rej) => {
      const t = Math.floor(Date.now() / 1000);
      const sig = `t=${t},v1=${createHmac("sha256", s2sSecret).update(`t=${t}`).digest("hex")}`;
      const r = httpRequest({ host: "127.0.0.1", port, path: "/mcp", method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "X-Gateway-S2S": sig, ...headers } },
      (resp) => { let text = ""; resp.on("data", (c) => (text += c)); resp.on("end", () => res({ status: resp.statusCode, text })); });
      r.on("error", rej);
      r.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "pmg_version_get", arguments: {} } }));
    });
    ticketLogins.length = 0;
    const ok = await post({ "X-PMG-Username": "hdr-user@pmg", "X-PMG-Password": "hdr-fake-password" });
    check(ok.status === 200 && ok.text.includes("4.0.0"), "gateway request with mixed-case headers succeeds");
    check(ticketLogins.includes("hdr-user@pmg"), "header credential reached the mock upstream");
    check(!ticketLogins.includes("env-user@pmg"), "env credential was NOT used");
    ticketLogins.length = 0;
    const missing = await post({});
    check(missing.status === 401, "gateway request without headers is rejected (401)");
    check(ticketLogins.length === 0, "no upstream login without header credentials (no env fallback)");
  } finally {
    child.kill();
  }

  console.log("\n[base-url] no default PMG_BASE_URL");
  await withServer({ PMG_BASE_URL: "" }, async (client) => {
    const result = await client.callTool({ name: "pmg_version_get", arguments: {} });
    check(result.isError === true && textOf(result).includes("PMG_BASE_URL is required"), "stdio with PMG_BASE_URL unset starts and tools return is_error");
  });
  const httpExit = await new Promise((resolveExit) => {
    const env = { ...process.env, MCP_TRANSPORT: "http", AUTH_MODE: "env", MCP_HTTP_PORT: "0", PORT: "0", LOG_LEVEL: "warn" };
    delete env.PMG_BASE_URL;
    const proc = spawn(process.execPath, [resolve(root, "dist/index.js")], { env, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    proc.stderr.on("data", (chunk) => (stderr += chunk));
    const timer = setTimeout(() => { proc.kill(); resolveExit({ code: "timeout", stderr }); }, 5000);
    proc.on("exit", (code) => { clearTimeout(timer); resolveExit({ code, stderr }); });
  });
  check(httpExit.code === 1 && httpExit.stderr.includes("PMG_BASE_URL is required"), "http mode with PMG_BASE_URL unset exits at startup");
} catch (error) {
  console.error("smoke test crashed:", error);
  failures.push("crash");
} finally {
  await new Promise((resolve) => mock.close(resolve));
}

if (failures.length > 0) {
  console.error(`\nSMOKE FAILED (${failures.length}): ${failures.join("; ")}`);
  process.exit(1);
}
console.log("\nSMOKE PASSED");
