import type { Tool, CallToolResult } from "@modelcontextprotocol/sdk/types.js";

export type { Tool, CallToolResult };

export type Tier = "read" | "write" | "admin";
export type PmgMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface ParamSpec {
  type: string;
  optional?: boolean;
  enum?: string[];
  description?: string;
  minimum?: number;
  maximum?: number;
  format?: string;
}

export interface EndpointSpec {
  tool: string;
  method: PmgMethod;
  path: string;
  tier: Tier;
  description: string;
  destructive?: boolean;
  params: Record<string, ParamSpec>;
}

export interface PmgCredentials {
  username: string;
  password: string;
  baseUrl: string;
}

export interface ApiResult {
  ok: boolean;
  data?: unknown;
  error?: {
    kind: "config" | "auth" | "network" | "http" | "upstream";
    message: string;
  };
}
