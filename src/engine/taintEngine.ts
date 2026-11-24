import type { IRNode, WorkflowIR } from '../types/workflowIR';

export const ENGINE_LIMITS = {
  MAX_FINDINGS: 200,
  MAX_BFS_VISITS: 5_000,
} as const;

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type RuleId =
  | 'LETHAL_TRIFECTA'
  | 'SHADOW_AI_NATIVE_BYPASS'
  | 'SHADOW_AI_DIRECT_HTTP'
  | 'TAINTED_DYNAMIC_URL';

export type FindingConfidence = 'confirmed' | 'potential';

export interface SecurityFinding {
  id: string;
  ruleId: RuleId;
  severity: Severity;
  confidence: FindingConfidence;
  title: string;
  description: string;
  remediation: string;
  /** Ordered list of node IDs showing the attack / taint path */
  pathNodeIds: string[];
  /** Human-readable node labels matching pathNodeIds */
  pathLabels: string[];
  /** Primary node IDs implicated in this finding */
  implicatedNodeIds: string[];
  /** True if the LLM in a trifecta path is routed through an allowlisted AI Gateway */
  mitigatedByGateway?: boolean;
}

export type RiskVerdict = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'CLEAN';

export interface ScanSummary {
  totalNodes: number;
  untrustedSourceCount: number;
  llmNodeCount: number;
  outboundSinkCount: number;
  gatewayRoutedCount: number;
  gatewayBypassCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  riskScore: number;
  verdict: RiskVerdict;
  truncatedFindings: boolean;
}

export interface ScanReport {
  workflowName: string;
  platform: WorkflowIR['platform'];
  scannedAtIso: string;
  findings: SecurityFinding[];
  summary: ScanSummary;
  parseWarnings: string[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
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

function computeRiskScore(findings: SecurityFinding[]): {
  score: number;
  verdict: RiskVerdict;
} {
  let score = 0;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') score += 45;
    else if (f.severity === 'HIGH') score += 25;
    else if (f.severity === 'MEDIUM') score += 12;
    else score += 5;
  }
  const capped = Math.min(100, score);

  if (findings.some((f) => f.severity === 'CRITICAL')) {
    return { score: Math.max(capped, 85), verdict: 'CRITICAL' };
  }
  if (findings.some((f) => f.severity === 'HIGH')) {
    return { score: Math.max(capped, 60), verdict: 'HIGH' };
  }
  if (findings.some((f) => f.severity === 'MEDIUM')) {
    return { score: Math.max(capped, 30), verdict: 'MEDIUM' };
  }
  return { score: capped, verdict: 'CLEAN' };
}

export function analyzeWorkflow(ir: WorkflowIR): ScanReport {
  const allNodes: IRNode[] = Object.values(ir.nodes);

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

  // Rule 1: LETHAL TRIFECTA (Untrusted Source -> LLM Processor -> Outbound Sink)
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

        const isConfirmedDataFlow = Boolean(srcToLlmData && llmToSinkData);
        const pathNodeIds = [...srcToLlmAny, ...llmToSinkAny.slice(1)];
        const isGatewayRouted = llm.ai.gatewayStatus === 'gateway_routed';

        const ok = pushFinding({
          id: `TRIFECTA-${source.id}-${llm.id}-${sink.id}`,
          ruleId: 'LETHAL_TRIFECTA',
          severity: isConfirmedDataFlow ? 'CRITICAL' : 'HIGH',
          confidence: isConfirmedDataFlow ? 'confirmed' : 'potential',
          title: isConfirmedDataFlow
            ? 'Confirmed Lethal Trifecta: Indirect Prompt Injection to Exfiltration'
            : 'Potential Lethal Trifecta: Untrusted Input Reaches LLM & Outbound Egress',
          description: isConfirmedDataFlow
            ? `Explicit data flow traces untrusted input from ${source.label} into LLM node ${llm.label}, whose output flows directly into outbound sink ${sink.label}. An attacker can inject instructions into the input payload to hijack the LLM and exfiltrate sensitive context.`
            : `Control-flow execution reaches LLM node ${llm.label} from untrusted source ${source.label} and continues to outbound sink ${sink.label}. Verify whether untrusted data enters the prompt or LLM output triggers this egress action.`,
          remediation:
            'Break the trifecta: (1) Enforce strict JSON schema validation / allowlisted enum outputs after the LLM, (2) require human-in-the-loop approval before outbound egress, and (3) route LLM traffic through a corporate AI Gateway with prompt-injection & DLP inspection.',
          pathNodeIds,
          pathLabels: labelsForPath(ir, pathNodeIds),
          implicatedNodeIds: [source.id, llm.id, sink.id],
          mitigatedByGateway: isGatewayRouted,
        });

        if (!ok) break trifectaLoop;
      }
    }
  }

  // Rule 2 & 3: SHADOW AI / CORPORATE AI GATEWAY BYPASS
  for (const llm of llms) {
    if (llm.ai.gatewayStatus === 'native_bypass') {
      const ok = pushFinding({
        id: `SHADOW-NATIVE-${llm.id}`,
        ruleId: 'SHADOW_AI_NATIVE_BYPASS',
        severity: 'HIGH',
        confidence: 'confirmed',
        title: `Native LLM Connector Bypasses Corporate AI Gateway (${llm.ai.provider ?? 'unknown'})`,
        description: `Module ${llm.label} uses a native vendor integration (${llm.rawType}), which hardcodes direct API calls to the model provider and bypasses enterprise AI Gateways, DLP policies, token budgets, and centralized audit logs.`,
        remediation:
          'Replace the native LLM module with an HTTP Request module pointed at your corporate AI Gateway (e.g., Cloudflare AI Gateway, Portkey, LiteLLM, or Palo Alto Prisma AIRS) using gateway-issued virtual keys.',
        pathNodeIds: [llm.id],
        pathLabels: [llm.label],
        implicatedNodeIds: [llm.id],
      });
      if (!ok) break;
    } else if (llm.ai.gatewayStatus === 'direct_http_bypass') {
      const ok = pushFinding({
        id: `SHADOW-HTTP-${llm.id}`,
        ruleId: 'SHADOW_AI_DIRECT_HTTP',
        severity: 'MEDIUM',
        confidence: 'confirmed',
        title: `Direct HTTP Call to Vendor LLM API (${llm.ai.provider ?? 'unknown'})`,
        description: `Module ${llm.label} calls ${llm.ai.targetUrl ?? 'a vendor LLM endpoint'} directly over HTTP instead of routing through an allowlisted AI Gateway, leaving prompt payloads invisible to security monitoring.`,
        remediation:
          'Update the HTTP target base URL to your approved corporate AI Gateway hostname and rotate the raw vendor API key stored in Make.com.',
        pathNodeIds: [llm.id],
        pathLabels: [llm.label],
        implicatedNodeIds: [llm.id],
      });
      if (!ok) break;
    }
  }

  // Rule 4: TAINTED DYNAMIC URL (SSRF / Attacker-Controlled Exfiltration Endpoint)
  const taintOrigins = [...sources, ...llms];
  ssrfLoop: for (const sink of sinks) {
    if (!sink.rawType.toLowerCase().startsWith('http:')) continue;
    const hasDynamicUrl = Boolean(sink.egressUrl && sink.egressUrl.includes('{{'));
    if (!hasDynamicUrl) continue;

    for (const origin of taintOrigins) {
      if (origin.id === sink.id) continue;
      const dataPath = findShortestPath(dataAdj, origin.id, sink.id);
      if (!dataPath) continue;

      const ok = pushFinding({
        id: `DYNAMIC-URL-${origin.id}-${sink.id}`,
        ruleId: 'TAINTED_DYNAMIC_URL',
        severity: 'HIGH',
        confidence: 'confirmed',
        title: 'SSRF / Dynamic Exfiltration URL Influenced by Untrusted or LLM Data',
        description: `HTTP module ${sink.label} interpolates dynamic IML expressions into its destination URL (${sink.egressUrl}) and receives tainted data from ${origin.label}. Attackers can redirect requests to internal metadata endpoints or attacker-controlled servers.`,
        remediation:
          'Hardcode the destination host and path in the HTTP module, or validate dynamic URL parameters against a strict domain allowlist before executing the request.',
        pathNodeIds: dataPath,
        pathLabels: labelsForPath(ir, dataPath),
        implicatedNodeIds: [origin.id, sink.id],
      });

      if (!ok) break ssrfLoop;
      break;
    }
  }

  // Deterministic ordering: CRITICAL -> HIGH -> MEDIUM -> LOW, then by ID
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.id.localeCompare(b.id);
  });

  const gatewayRoutedCount = llms.filter((n) => n.ai.gatewayStatus === 'gateway_routed').length;
  const gatewayBypassCount = llms.filter(
    (n) => n.ai.gatewayStatus === 'native_bypass' || n.ai.gatewayStatus === 'direct_http_bypass'
  ).length;

  const { score, verdict } = computeRiskScore(findings);

  return {
    workflowName: ir.name,
    platform: ir.platform,
    scannedAtIso: new Date().toISOString(),
    findings,
    summary: {
      totalNodes: allNodes.length,
      untrustedSourceCount: sources.length,
      llmNodeCount: llms.length,
      outboundSinkCount: sinks.length,
      gatewayRoutedCount,
      gatewayBypassCount,
      criticalCount: findings.filter((f) => f.severity === 'CRITICAL').length,
      highCount: findings.filter((f) => f.severity === 'HIGH').length,
      mediumCount: findings.filter((f) => f.severity === 'MEDIUM').length,
      lowCount: findings.filter((f) => f.severity === 'LOW').length,
      riskScore: score,
      verdict,
      truncatedFindings,
    },
    parseWarnings: ir.parseWarnings,
  };
}