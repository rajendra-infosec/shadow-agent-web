export type WorkflowPlatform = 'make' | 'n8n' | 'zapier';

export type AnalysisStatus = 'COMPLETE' | 'PARTIAL';

export type NodeSecurityRole =
  | 'untrusted_source'
  | 'llm_processor'
  | 'outbound_sink'
  | 'router'
  | 'transform';

export type AIGatewayStatus =
  | 'none'
  | 'native_bypass'
  | 'direct_http_bypass'
  | 'gateway_routed';

export interface AINodeMetadata {
  isLLM: boolean;
  provider?: string;
  model?: string;
  gatewayStatus: AIGatewayStatus;
  /** Redacted target URL (credentials, query values, and fragments stripped) */
  targetUrl?: string;
}

export interface IRNode {
  id: string;
  platform: WorkflowPlatform;
  rawType: string;
  label: string;
  roles: NodeSecurityRole[];
  ai: AINodeMetadata;
  /** Redacted outbound URL if this node is an HTTP/webhook sink */
  egressUrl?: string;
  /** True if {{...}} IML expressions appear in scheme, authority, hostname, or port */
  egressUrlHasDynamicHost?: boolean;
  /** True if {{...}} IML expressions appear in URL path or query parameters */
  egressUrlHasDynamicPathOrQuery?: boolean;
  /** Module IDs referenced specifically inside the destination URL field */
  urlReferencedNodeIds?: string[];
  /** All upstream module IDs referenced anywhere in this node's config via {{id.*}} */
  referencedNodeIds: string[];
  branchDepth: number;
  hasFilter: boolean;
}

export interface IREdge {
  from: string;
  to: string;
  kind: 'control_flow' | 'data_flow';
  routeIndex?: number;
  isErrorHandler?: boolean;
}

export interface WorkflowIR {
  platform: WorkflowPlatform;
  name: string;
  analysisStatus?: AnalysisStatus;
  nodes: Record<string, IRNode>;
  edges: IREdge[];
  entryNodeIds: string[];
  parseWarnings: string[];
}