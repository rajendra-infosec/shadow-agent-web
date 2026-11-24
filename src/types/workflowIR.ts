export type Platform = 'make' | 'n8n';

export type TaintRole =
  | 'untrusted_source'
  | 'llm_processor'
  | 'outbound_sink'
  | 'router'
  | 'transform'
  | 'unknown';

export type AIGatewayStatus =
  | 'none'
  | 'native_bypass'       // Native vendor connector (e.g., openai-gpt-3:*) cannot route via corp AI Gateway
  | 'direct_http_bypass'  // Raw HTTP request hitting vendor LLM API directly
  | 'gateway_routed';     // HTTP request routed through a recognized/allowlisted AI Gateway

export interface AIMetadata {
  isLLM: boolean;
  provider?: string;
  gatewayStatus: AIGatewayStatus;
  targetUrl?: string;
}

export interface IRNode {
  id: string;
  platform: Platform;
  /** Raw module identifier, e.g., "openai-gpt-3:CreateCompletion" */
  rawType: string;
  /** Human-readable display label (sanitized plain text only) */
  label: string;
  /** Security roles assigned to this node */
  roles: TaintRole[];
  ai: AIMetadata;
  /** Validated http(s) URL if statically extractable */
  egressUrl?: string;
  /** Upstream node IDs explicitly referenced via expressions (e.g., Make IML {{1.body}}) */
  referencedNodeIds: string[];
  /** Nesting depth inside routers (0 = top-level flow) */
  branchDepth: number;
  /** True if a conditional filter gates execution into this node */
  hasFilter: boolean;
}

export type EdgeKind = 'control_flow' | 'data_flow';

export interface IREdge {
  from: string;
  to: string;
  kind: EdgeKind;
  /** Present on the first node of a router branch */
  routeIndex?: number;
}

export interface WorkflowIR {
  platform: Platform;
  name: string;
  nodes: Record<string, IRNode>;
  edges: IREdge[];
  entryNodeIds: string[];
  parseWarnings: string[];
}
