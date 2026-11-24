import type { AnalysisStatus, IRNode, WorkflowIR } from '../types/workflowIR';

export const ENGINE_LIMITS = {
  MAX_FINDINGS: 200,
  MAX_BFS_VISITS: 5_000,
} as const;

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export type RuleId =
  | 'CANDIDATE_TRIFECTA_CHAIN'
  | 'NATIVE_LLM_CONNECTOR_OBSERVED'
  | 'DIRECT_PROVIDER_ENDPOINT_DECLARED'
  | 'TAINTED_DYNAMIC_HOST';

export type EvidenceBasis = 'explicit_mapping' | 'control_flow_only' | 'static_config';

export interface SecurityFinding {
  id: string;
  ruleId: RuleId;
  severity: Severity;
  evidenceBasis: EvidenceBasis;
  title: string;
  description: string;
  remediation: string;
  /** Ordered list of node IDs showing the observed graph path */
  pathNodeIds: string[];
  /** Human-readable node labels matching pathNodeIds */
  pathLabels: string[];
  /** Primary node IDs implicated in this finding */
  implicatedNodeIds: string[];
  /** True if the LLM node's hostname matched an allowlisted AI Gateway (policy enforcement unverified statically) */
  gatewayEndpointMatched?: boolean;
}

export type ScanVerdict =
  | 'REVIEW_REQUIRED'
  | 'NO_CANDIDATES_FOUND'
  | 'INCOMPLETE_ANALYSIS';

export interface ScanSummary {
  analysisStatus: AnalysisStatus;
  verdict: ScanVerdict;
  totalNodes: number;
  untrustedSourceCount: number;
  llmNodeCount: number;
  outboundSinkCount: number;
  gatewayHostMatchedCount: number;
  directOrNativeLlmCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  truncatedFindings: boolean;
}

export interface ScanReport {
  workflowName: string;
  platform: WorkflowIR['platform'];
  analysisStatus: AnalysisStatus;
  scannedAtIso: string;
  findings: SecurityFinding[];
  summary: ScanSummary;
  parseWarnings: string[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  HIGH: 0,
  MEDIUM: 1,
  LOW: 2,
};

function hasNode(ir: WorkflowIR, id: string): boolean {
  return Object.prototype.hasOwnProperty.call(ir.nodes, id);
}

function buildAdjacency(
  ir: WorkflowIR,
  allowedKinds: ReadonlySet<'control_flow' | 'data_flow'>
): Map<string, string[]> {
  const adj = new Map<string, string[]>();

  for (const edge of ir.edges) {
    if (!allowedKinds.has(edge.kind)) continue;
    if (!hasNode(ir, edge.from) || !hasNode(ir, edge.to)) continue;

    let neighbors = adj.get(edge.from);
    if (!neighbors) {
      neighbors = [];
      adj.set(edge.from, neighbors);
    }
    if (!neighbors.includes(edge.to)) {
      neighbors.push(edge.to);
    }
  }

  return adj;
}

/**
 * Cycle-safe, bounded shortest-path BFS from startId to targetId.
 * Returns the ordered array of node IDs [startId, ..., targetId], or null if unreachable.
 */
function findShortestPath(
  adj: Map<string, string[]>,
  startId: string,
  targetId: string
): string[] | null {
  if (startId === targetId) return [startId];

  const queue: string[] = [startId];
  let head = 0;

  const visited = new Set<string>([startId]);
  const parent = new Map<string, string | null>([[startId, null]]);

  while (head < queue.length && visited.size <= ENGINE_LIMITS.MAX_BFS_VISITS) {
    const current = queue[head++];
    const neighbors = adj.get(current);
    if (!neighbors) continue;

    for (const next of neighbors) {
      if (visited.has(next)) continue;
      visited.add(next);
      parent.set(next, current);

      if (next === targetId) {
        const path: string[] = [];
        let cursor: string | null | undefined = targetId;
        while (cursor !== null && cursor !== undefined) {
          path.push(cursor);
          cursor = parent.get(cursor);
        }
        return path.reverse();
      }

      queue.push(next);
    }
  }

  return null;
}

function labelsForPath(ir: WorkflowIR, ids: string[]): string[] {
  return ids.map((id) => (hasNode(ir, id) ? ir.nodes[id].label : `#${id}`));
}

export function analyzeWorkflow(ir: WorkflowIR): ScanReport {
  const allNodes: IRNode[] = Object.values(ir.nodes);
  const analysisStatus: AnalysisStatus = ir.analysisStatus ?? 'COMPLETE';

  const sources = allNodes.filter((n) => n.roles.includes('untrusted_source'));
  const llms = allNodes.filter((n) => n.roles.includes('llm_processor'));
  const sinks = allNodes.filter((n) => n.roles.includes('outbound_sink'));

  const dataAdj = buildAdjacency(ir, new Set(['data_flow']));
  const combinedAdj = buildAdjacency(ir, new Set(['control_flow', 'data_flow']));

  const findings: SecurityFinding[] = [];
  let truncatedFindings = false;

  const pushFinding = (finding: SecurityFinding): boolean => {
    if (findings.length >= ENGINE_LIMITS.MAX_FINDINGS) {
      truncatedFindings = true;
      return false;
    }
    findings.push(finding);
    return true;
  };

  // Rule 1: CANDIDATE TRIFECTA CHAIN (Input Source -> LLM Processor -> Outbound Sink)
  trifectaLoop: for (const source of sources) {
    for (const llm of llms) {
      if (source.id === llm.id) continue;

      const srcToLlmData = findShortestPath(dataAdj, source.id, llm.id);
      const srcToLlmAny = srcToLlmData ?? findShortestPath(combinedAdj, source.id, llm.id);
      if (!srcToLlmAny) continue;

      for (const sink of sinks) {
        if (sink.id === llm.id || sink.id === source.id) continue;

        const llmToSinkData = findShortestPath(dataAdj, llm.id, sink.id);
        const llmToSinkAny = llmToSinkData ?? findShortestPath(combinedAdj, llm.id, sink.id);
        if (!llmToSinkAny) continue;

        const hasExplicitMapping = Boolean(srcToLlmData && llmToSinkData);
        const pathNodeIds = [...srcToLlmAny, ...llmToSinkAny.slice(1)];
        const gatewayEndpointMatched = llm.ai.gatewayStatus === 'gateway_routed';

        const ok = pushFinding({
          id: `CHAIN-${source.id}-${llm.id}-${sink.id}`,
          ruleId: 'CANDIDATE_TRIFECTA_CHAIN',
          severity: hasExplicitMapping ? 'HIGH' : 'MEDIUM',
          evidenceBasis: hasExplicitMapping ? 'explicit_mapping' : 'control_flow_only',
          title: hasExplicitMapping
            ? 'Explicit Mapping Chain Observed: Input → LLM → Outbound Sink'
            : 'Candidate Control-Flow Path: Input → LLM → Outbound Sink',
          description: hasExplicitMapping
            ? `Explicit IML mapping references connect ${source.label} into LLM node ${llm.label} and from ${llm.label} into outbound sink ${sink.label}. Static analysis cannot verify whether private data is present in context or whether runtime filters block abuse; manual review is required.`
            : `Control-flow execution reaches ${llm.label} from ${source.label} and continues to outbound sink ${sink.label} without an explicit IML reference on both legs. Verify whether untrusted input enters the prompt or LLM output triggers this egress action.`,
          remediation:
            'Review data sensitivity and trust boundaries: (1) enforce strict JSON schema / allowlisted enum validation after the LLM, (2) require human approval before sensitive outbound actions, and (3) verify whether prompt-injection and DLP controls are enforced upstream.',
          pathNodeIds,
          pathLabels: labelsForPath(ir, pathNodeIds),
          implicatedNodeIds: [source.id, llm.id, sink.id],
          gatewayEndpointMatched,
        });

        if (!ok) break trifectaLoop;
      }
    }
  }

  // Rule 2 & 3: AI GATEWAY GOVERNANCE EVIDENCE
  for (const llm of llms) {
    if (llm.ai.gatewayStatus === 'native_bypass') {
      const ok = pushFinding({
        id: `NATIVE-LLM-${llm.id}`,
        ruleId: 'NATIVE_LLM_CONNECTOR_OBSERVED',
        severity: 'MEDIUM',
        evidenceBasis: 'static_config',
        title: `Native LLM Connector Observed (${llm.ai.provider ?? 'unknown'})`,
        description: `Module ${llm.label} is configured with a native vendor connector (${llm.rawType}). Native connectors typically send traffic directly to the vendor API rather than a custom corporate AI Gateway hostname; verify external network or governance controls.`,
        remediation:
          'If your organization mandates centralized AI Gateway routing, replace the native connector with an HTTP module targeting your allowlisted gateway hostname using gateway-managed credentials.',
        pathNodeIds: [llm.id],
        pathLabels: [llm.label],
        implicatedNodeIds: [llm.id],
      });
      if (!ok) break;
    } else if (llm.ai.gatewayStatus === 'direct_http_bypass') {
      const ok = pushFinding({
        id: `DIRECT-LLM-${llm.id}`,
        ruleId: 'DIRECT_PROVIDER_ENDPOINT_DECLARED',
        severity: 'MEDIUM',
        evidenceBasis: 'static_config',
        title: `Direct Provider LLM Endpoint Declared (${llm.ai.provider ?? 'unknown'})`,
        description: `Module ${llm.label} declares ${llm.ai.targetUrl ?? 'a vendor LLM endpoint'} over HTTP rather than an allowlisted AI Gateway hostname. Verify whether this bypasses required prompt logging or DLP controls.`,
        remediation:
          'Point the HTTP target base URL at your approved corporate AI Gateway hostname and rotate any raw vendor API keys stored in the connection.',
        pathNodeIds: [llm.id],
        pathLabels: [llm.label],
        implicatedNodeIds: [llm.id],
      });
      if (!ok) break;
    }
  }

  // Rule 4: TAINTED DYNAMIC HOST (Potential SSRF / Destination Host Manipulation)
  // Only fires when {{...}} appears in the URL scheme, authority, hostname, or port — NOT fixed-host query params.
  const taintOrigins = [...sources, ...llms];
  ssrfLoop: for (const sink of sinks) {
    if (!sink.rawType.toLowerCase().startsWith('http:')) continue;
    if (!sink.egressUrlHasDynamicHost) continue;

    const urlRefs = sink.urlReferencedNodeIds ?? [];
    for (const origin of taintOrigins) {
      if (origin.id === sink.id) continue;

      let matchedPath: string[] | null = null;
      if (urlRefs.includes(origin.id)) {
        matchedPath = [origin.id, sink.id];
      } else {
        for (const urlRefId of urlRefs) {
          const upstreamPath = findShortestPath(dataAdj, origin.id, urlRefId);
          if (upstreamPath) {
            matchedPath = [...upstreamPath, sink.id];
            break;
          }
        }
      }

      if (!matchedPath) continue;

      const ok = pushFinding({
        id: `DYNAMIC-HOST-${origin.id}-${sink.id}`,
        ruleId: 'TAINTED_DYNAMIC_HOST',
        severity: 'HIGH',
        evidenceBasis: 'explicit_mapping',
        title: 'Potential SSRF: Dynamic Hostname/Authority Influenced by Input or LLM Data',
        description: `HTTP module ${sink.label} interpolates an IML expression into the destination hostname/authority (${sink.egressUrl ?? '[redacted]'}) with a data-flow path from ${origin.label}. Attacker-influenced hostnames can redirect outbound requests to unintended or internal destinations.`,
        remediation:
          'Hardcode the destination scheme and hostname in the HTTP module, or validate dynamic host values against a strict allowlist before making the request.',
        pathNodeIds: matchedPath,
        pathLabels: labelsForPath(ir, matchedPath),
        implicatedNodeIds: [origin.id, sink.id],
      });

      if (!ok) break ssrfLoop;
      break;
    }
  }

  // Deterministic ordering: HIGH -> MEDIUM -> LOW, then by ID
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.id.localeCompare(b.id);
  });

  const gatewayHostMatchedCount = llms.filter((n) => n.ai.gatewayStatus === 'gateway_routed').length;
  const directOrNativeLlmCount = llms.filter(
    (n) => n.ai.gatewayStatus === 'native_bypass' || n.ai.gatewayStatus === 'direct_http_bypass'
  ).length;

  let verdict: ScanVerdict;
  if (findings.length > 0) {
    verdict = 'REVIEW_REQUIRED';
  } else if (analysisStatus === 'PARTIAL') {
    verdict = 'INCOMPLETE_ANALYSIS';
  } else {
    verdict = 'NO_CANDIDATES_FOUND';
  }

  return {
    workflowName: ir.name,
    platform: ir.platform,
    analysisStatus,
    scannedAtIso: new Date().toISOString(),
    findings,
    summary: {
      analysisStatus,
      verdict,
      totalNodes: allNodes.length,
      untrustedSourceCount: sources.length,
      llmNodeCount: llms.length,
      outboundSinkCount: sinks.length,
      gatewayHostMatchedCount,
      directOrNativeLlmCount,
      highCount: findings.filter((f) => f.severity === 'HIGH').length,
      mediumCount: findings.filter((f) => f.severity === 'MEDIUM').length,
      lowCount: findings.filter((f) => f.severity === 'LOW').length,
      truncatedFindings,
    },
    parseWarnings: ir.parseWarnings,
  };
}