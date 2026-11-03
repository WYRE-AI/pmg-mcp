import { ENDPOINTS } from "./endpoints.js";
import type { Tier } from "./utils/types.js";

export const TOOL_TIERS: Record<string, { tier: Tier; destructive: boolean }> = Object.fromEntries(
  ENDPOINTS.map((endpoint) => [
    endpoint.tool,
    { tier: endpoint.tier, destructive: endpoint.destructive ?? false },
  ]),
);

export const TOOL_NAMES: readonly string[] = ENDPOINTS.map((endpoint) => endpoint.tool);
