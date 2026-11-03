import { TOOL_TIERS } from "./tool-tiers.js";
import type { Tier } from "./utils/types.js";

export const DEFAULT_TIERS: readonly Tier[] = ["read"];

export function getEnabledTiers(env: NodeJS.ProcessEnv = process.env): readonly Tier[] {
  const raw = (env.PMG_TOOL_TIERS ?? "read").trim().toLowerCase();
  if (!raw) return [...DEFAULT_TIERS];
  const tiers = raw.split(",").map((tier) => tier.trim().toLowerCase()).filter(Boolean);
  if (tiers.length === 0) return [...DEFAULT_TIERS];
  const invalid = tiers.filter((tier) => tier !== "read" && tier !== "write" && tier !== "admin");
  if (invalid.length > 0) {
    throw new Error(`Invalid PMG_TOOL_TIERS value: ${raw}`);
  }
  return [...new Set(tiers)] as Tier[];
}

export function isToolEnabled(tool: string, enabledTiers: readonly Tier[]): boolean {
  const tier = TOOL_TIERS[tool]?.tier;
  if (!tier) return false;
  return enabledTiers.includes(tier);
}
