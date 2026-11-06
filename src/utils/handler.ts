import type { CallToolResult, EndpointSpec, PmgCredentials, Tool } from "./types.js";
import { execute } from "./client.js";
import { getEnabledTiers, isToolEnabled } from "../tiers.js";
import { TOOL_TIERS } from "../tool-tiers.js";
import { ENDPOINTS } from "../endpoints.js";

function errorResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }], isError: true };
}

export function getEndpoint(tool: string): EndpointSpec | undefined {
  return ENDPOINTS.find((endpoint) => endpoint.tool === tool);
}

function toTool(endpoint: EndpointSpec) {
  const required = Object.entries(endpoint.params)
    .filter(([, param]) => !param.optional)
    .map(([key]) => key);
  return {
    name: endpoint.tool,
    description:
      endpoint.destructive === true && !endpoint.description.startsWith("⚠ DESTRUCTIVE")
        ? `⚠ DESTRUCTIVE ${endpoint.description}`
        : endpoint.description,
    inputSchema: {
      type: "object",
      properties: Object.fromEntries(
        Object.entries(endpoint.params).map(([key, param]) => [
          key,
          {
            type: param.type === "integer" ? "number" : param.type,
            enum: param.enum,
            description: param.description,
            minimum: param.minimum,
            maximum: param.maximum,
          },
        ]),
      ),
      required,
    },
    annotations: {
      destructiveHint: endpoint.destructive === true,
      readOnlyHint: endpoint.method === "GET",
    },
  };
}

export function listTools(tiers: readonly string[] = getEnabledTiers()): Tool[] {
  const enabled = new Set(tiers);
  const tools = Object.entries(TOOL_TIERS)
    .map(([tool, info]) => ({ tool, info }))
    .filter(({ info }) => enabled.has(info.tier))
    .map(({ tool }) => getEndpoint(tool))
    .filter((endpoint): endpoint is EndpointSpec => Boolean(endpoint));
  return tools.map(toTool) as Tool[];
}

export async function callTool(
  tool: string,
  args: Record<string, unknown>,
  creds: PmgCredentials,
): Promise<CallToolResult> {
  const endpoint = getEndpoint(tool);
  if (!endpoint) return errorResult(`Unknown tool: ${tool}`);
  if (!isToolEnabled(tool, getEnabledTiers())) {
    return errorResult(`Tool ${tool} requires the "${TOOL_TIERS[tool].tier}" tier, which is not enabled.`);
  }
  const result = await execute(endpoint, args, creds);
  if (!result.ok) return errorResult(result.error?.message ?? "PMG request failed.");
  return { content: [{ type: "text", text: JSON.stringify(result.data ?? null) }] };
}
