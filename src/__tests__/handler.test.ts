import { beforeEach, describe, expect, it, vi } from "vitest";
import { callTool, listTools } from "../utils/handler.js";
import { clearTicketCache } from "../utils/client.js";
import { TOOL_TIERS } from "../tool-tiers.js";
import type { PmgCredentials } from "../utils/types.js";

const credentials: PmgCredentials = {
  username: "mcp@pmg",
  password: "super-secret-password",
  baseUrl: "https://pmg.example.com:8006",
};

beforeEach(() => {
  clearTicketCache();
  vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string) =>
        new URL(input).pathname === "/api2/json/access/ticket"
          ? new Response(JSON.stringify({ data: { ticket: "ticket-123", CSRFPreventionToken: "csrf-123", username: "mcp@pmg" } }), { status: 200 })
          : new Response(JSON.stringify({ data: { version: "4.0.0" } }), { status: 200 }),
      ),
    );
});

describe("PMG tool registry", () => {
  it("lists exactly 55 read, 17 write, and 16 admin tools", () => {
    const tools = listTools(["read", "write", "admin"]);
    expect(tools).toHaveLength(88);
    const read = Object.values(TOOL_TIERS).filter((info) => info.tier === "read").length;
    const write = Object.values(TOOL_TIERS).filter((info) => info.tier === "write").length;
    const admin = Object.values(TOOL_TIERS).filter((info) => info.tier === "admin").length;
    expect(read).toBe(55);
    expect(write).toBe(17);
    expect(admin).toBe(16);
  });
});

describe("PMG tool call", () => {
  it("performs a mocked read call end to end", async () => {
    const result = await callTool("pmg_version_get", {}, credentials);
    expect(result.isError).toBeUndefined();
    expect(result.content[0]).toMatchObject({ type: "text", text: JSON.stringify({ data: { version: "4.0.0" } }) });
  });
});
