#!/usr/bin/env node
import { createServer } from "node:http";
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

const mock = createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    res.setHeader("Content-Type", "application/json");
    if (req.method === "POST" && req.url === "/api2/json/access/ticket") {
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
