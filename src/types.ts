export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  probeId: string;
  severity: Severity;
  title: string;
  detail: string;
  target: string;
  evidence?: unknown;
}

export interface ToolSummary {
  name: string;
  description?: string;
  inputSchema: unknown;
}

export interface ResourceSummary {
  uri: string;
  name?: string;
  description?: string;
}

export interface PromptSummary {
  name: string;
  description?: string;
}

export interface ServerCapabilitySnapshot {
  serverName?: string;
  serverVersion?: string;
  tools: ToolSummary[];
  resources: ResourceSummary[];
  prompts: PromptSummary[];
}
