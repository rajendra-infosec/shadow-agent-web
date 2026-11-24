import type {
  AIMetadata,
  IREdge,
  IRNode,
  TaintRole,
  WorkflowIR,
} from '../types/workflowIR';

/** Hard security limits to prevent client-side DoS / stack exhaustion */
export const PARSER_LIMITS = {
  MAX_INPUT_BYTES: 5 * 1024 * 1024, // 5 MB
  MAX_ROUTER_DEPTH: 32,
  MAX_OBJECT_DEPTH: 32,
  MAX_NODES: 2_000,
  MAX_STRING_SCAN_LEN: 50_000,
  MAX_IML_BLOCKS_PER_STRING: 500,
} as const;

interface RawMakeModule {
  id: number;
  module: string;
  parameters?: unknown;
  mapper?: unknown;
  filter?: unknown;
  metadata?: unknown;
  routes?: unknown;
  onerror?: unknown;
}

export interface MakeAdapterOptions {
  /** Extra corporate AI Gateway hostnames (e.g., ["ai-gw.corp.internal"]) */
  allowedGatewayHosts?: string[];
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const DEFAULT_GATEWAY_HOSTS = [
  'gateway.ai.cloudflare.com',
  'api.portkey.ai',
  'api.helicone.ai',
  'oai.helicone.ai',
  'anthropic.helicone.ai',
  'gateway.litellm.ai',
];

const DIRECT_LLM_API_HOSTS: Record<string, string> = {
  'api.openai.com': 'openai',
  'api.anthropic.com': 'anthropic',
  'generativelanguage.googleapis.com': 'google-gemini',
  'api.mistral.ai': 'mistral',
  'api.cohere.ai': 'cohere',
  'api.cohere.com': 'cohere',
  'api.groq.com': 'groq',
  'api.perplexity.ai': 'perplexity',
  'api.deepseek.com': 'deepseek',
};

const NATIVE_LLM_PREFIXES: Record<string, string> = {
  'openai-gpt-3:': 'openai',
  'openai:': 'openai',
  'anthropic-claude:': 'anthropic',
  'anthropic:': 'anthropic',
  'google-gemini:': 'google-gemini',
  'gemini-ai:': 'google-gemini',
  'mistral:': 'mistral',
  'perplexity:': 'perplexity',
  'cohere:': 'cohere',
  'groq:': 'groq',
  'huggingface:': 'huggingface',
  'azure-openai:': 'azure-openai',
};

const UNTRUSTED_SOURCE_PATTERNS: RegExp[] = [
  /^gateway:CustomWebHook/i,
  /^gateway:CustomMailHook/i,
  /^google-email:Trigger/i,
  /^google-email:Watch/i,
  /^email:Trigger/i,
  /^email:Watch/i,
  /^microsoft-email:Trigger/i,
  /^microsoft-email:Watch/i,
  /^slack:Watch/i,
  /^typeform:/i,
  /^tally:/i,
  /^google-forms:/i,
  /^webhook/i,
  /^rss:/i,
  /^zendesk:Watch/i,
  /^jira:Watch/i,
  /^github:Watch/i,
  /^telegram:Watch/i,
  /^whatsapp/i,
];

const OUTBOUND_SINK_PATTERNS: RegExp[] = [
  /^http:ActionSendData/i,
  /^http:ActionMakeRequest/i,
  /^http:ActionGetFile/i,
  /^google-email:ActionSendEmail/i,
  /^google-email:sendEmail/i,
  /^email:ActionSendEmail/i,
  /^microsoft-email:ActionSendEmail/i,
  /^slack:CreateMessage/i,
  /^slack:ActionPostMessage/i,
  /^discord:/i,
  /^telegram:Send/i,
  /^twilio:/i,
  /^sendgrid:/i,
  /^mailgun:/i,
  /^google-sheets:addRow/i,
  /^google-drive:upload/i,
  /^aws-s3:upload/i,
  /^github:create/i,
];

const ROUTER_MODULES = new Set(['builtin:BasicRouter']);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Strips prototype-pollution keys during JSON parsing */
function safeJsonParse(raw: string): unknown {
  if (raw.length > PARSER_LIMITS.MAX_INPUT_BYTES) {
    throw new Error(
      `Blueprint exceeds maximum allowed size (${PARSER_LIMITS.MAX_INPUT_BYTES / (1024 * 1024)} MB).`
    );
  }
  return JSON.parse(raw, (key: string, value: unknown) => {
    if (FORBIDDEN_KEYS.has(key)) {
      return undefined;
    }
    return value;
  });
}

/**
 * ReDoS-safe linear O(n) extractor for Make.com IML references such as:
 *   {{1.body}}, {{3.choices[].message.content}}, {{replace(12.text; "a"; "b")}}
 */
function extractRefsFromString(input: string, refs: Set<string>): void {
  const bounded =
    input.length > PARSER_LIMITS.MAX_STRING_SCAN_LEN
      ? input.slice(0, PARSER_LIMITS.MAX_STRING_SCAN_LEN)
      : input;

  let cursor = 0;
  let blocksScanned = 0;

  while (cursor < bounded.length && blocksScanned < PARSER_LIMITS.MAX_IML_BLOCKS_PER_STRING) {
    const start = bounded.indexOf('{{', cursor);
    if (start === -1) break;

    const end = bounded.indexOf('}}', start + 2);
    if (end === -1) break; // Unclosed {{ — stop immediately without backtracking

    const expr = bounded.slice(start + 2, end);
    const idRegex = /(?:^|[^a-zA-Z0-9_])(\d+)\.[a-zA-Z_`]/g;
    let match: RegExpExecArray | null;
    while ((match = idRegex.exec(expr)) !== null) {
      refs.add(match[1]);
    }

    cursor = end + 2;
    blocksScanned += 1;
  }
}

function extractIMLReferences(
  value: unknown,
  refs: Set<string>,
  depth = 0
): void {
  if (depth > PARSER_LIMITS.MAX_OBJECT_DEPTH || value === null || value === undefined) {
    return;
  }

  if (typeof value === 'string') {
    extractRefsFromString(value, refs);
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      extractIMLReferences(item, refs, depth + 1);
    }
    return;
  }

  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      extractIMLReferences(v, refs, depth + 1);
    }
  }
}

/**
 * Extracts and validates an http(s) URL from HTTP/Webhook module parameters.
 * Rejects dangerous protocols (e.g., javascript:, data:, file:) fail-closed.
 */
function extractSafeTargetUrl(
  mod: RawMakeModule,
  warnings: string[]
): { url?: string; hostname?: string } {
  const mapper = isPlainRecord(mod.mapper) ? mod.mapper : undefined;
  const params = isPlainRecord(mod.parameters) ? mod.parameters : undefined;

  const candidates = [
    mapper?.url,
    mapper?.uri,
    mapper?.endpoint,
    params?.url,
  ];

  for (const candidate of candidates) {
    if (typeof candidate !== 'string') continue;
    const trimmed = candidate.trim();
    if (!trimmed) continue;

    // Replace dynamic IML tokens only for URL structural validation
    const sanitizedForParse = trimmed.replace(/\{\{[^{}]*\}\}/g, 'placeholder');
    try {
      const parsed = new URL(sanitizedForParse);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        warnings.push(
          `Module #${mod.id} contains non-HTTP(S) URL protocol "${parsed.protocol}" — ignored for safety.`
        );
        return {};
      }
      return {
        url: trimmed,
        hostname: parsed.hostname.toLowerCase(),
      };
    } catch {
      warnings.push(
        `Module #${mod.id} uses a dynamic or non-standard URL expression ("${trimmed.slice(0, 60)}").`
      );
      return {};
    }
  }

  return {};
}

function classifyAI(
  mod: RawMakeModule,
  targetUrl: string | undefined,
  hostname: string | undefined,
  allowedGateways: Set<string>
): AIMetadata {
  const rawType = mod.module.toLowerCase();

  // 1. Native LLM connectors bypass corporate AI Gateways by architecture
  for (const [prefix, provider] of Object.entries(NATIVE_LLM_PREFIXES)) {
    if (rawType.startsWith(prefix)) {
      return {
        isLLM: true,
        provider,
        gatewayStatus: 'native_bypass',
      };
    }
  }

  // 2. Generic HTTP module calling an AI endpoint directly vs. through a gateway
  if (rawType.startsWith('http:') && hostname) {
    if (allowedGateways.has(hostname)) {
      return {
        isLLM: true,
        provider: 'gateway',
        gatewayStatus: 'gateway_routed',
        targetUrl,
      };
    }

    const directProvider = DIRECT_LLM_API_HOSTS[hostname];
    if (directProvider) {
      return {
        isLLM: true,
        provider: directProvider,
        gatewayStatus: 'direct_http_bypass',
        targetUrl,
      };
    }
  }

  return { isLLM: false, gatewayStatus: 'none' };
}

function classifyRoles(mod: RawMakeModule, ai: AIMetadata): TaintRole[] {
  const roles = new Set<TaintRole>();
  const rawType = mod.module;

  if (ROUTER_MODULES.has(rawType) || (Array.isArray(mod.routes) && mod.routes.length > 0)) {
    roles.add('router');
    return Array.from(roles);
  }

  if (UNTRUSTED_SOURCE_PATTERNS.some((rx) => rx.test(rawType))) {
    roles.add('untrusted_source');
  }

  if (ai.isLLM) {
    roles.add('llm_processor');
  }

  if (OUTBOUND_SINK_PATTERNS.some((rx) => rx.test(rawType)) && !ai.isLLM) {
    roles.add('outbound_sink');
  }

  if (roles.size === 0) {
    if (
      rawType.startsWith('builtin:') ||
      rawType.startsWith('util:') ||
      rawType.startsWith('json:')
    ) {
      roles.add('transform');
    } else {
      roles.add('unknown');
    }
  }

  return Array.from(roles);
}

function formatLabel(mod: RawMakeModule): string {
  const meta = isPlainRecord(mod.metadata) ? mod.metadata : undefined;
  const designer = meta && isPlainRecord(meta.designer) ? meta.designer : undefined;
  const customName = designer?.name;

  if (typeof customName === 'string' && customName.trim().length > 0) {
    return `${customName.trim().slice(0, 80)} (#${mod.id})`;
  }
  return `${mod.module.slice(0, 80)} (#${mod.id})`;
}

function hasFilterConditions(mod: RawMakeModule): boolean {
  const filter = isPlainRecord(mod.filter) ? mod.filter : undefined;
  return Boolean(filter && Array.isArray(filter.conditions) && filter.conditions.length > 0);
}

function isValidMakeModule(candidate: unknown): candidate is RawMakeModule {
  if (!isPlainRecord(candidate)) return false;
  return (
    typeof candidate.id === 'number' &&
    Number.isInteger(candidate.id) &&
    candidate.id >= 0 &&
    typeof candidate.module === 'string' &&
    candidate.module.trim().length > 0
  );
}

export function parseMakeBlueprint(
  input: unknown,
  options: MakeAdapterOptions = {}
): WorkflowIR {
  const raw: unknown = typeof input === 'string' ? safeJsonParse(input) : input;

  if (!isPlainRecord(raw) || !Array.isArray(raw.flow)) {
    throw new Error('Invalid Make.com blueprint: expected a JSON object with a top-level "flow" array.');
  }

  const allowedGateways = new Set(
    [...DEFAULT_GATEWAY_HOSTS, ...(options.allowedGatewayHosts ?? [])]
      .map((h) => h.trim().toLowerCase())
      .filter((h) => h.length > 0)
  );

  // Null-prototype map prevents prototype key collisions on node lookup
  const nodes: Record<string, IRNode> = Object.create(null) as Record<string, IRNode>;
  const edges: IREdge[] = [];
  const entryNodeIds: string[] = [];
  const parseWarnings: string[] = [];
  let nodeCount = 0;

  function walkFlow(
    flow: unknown[],
    parentId: string | null,
    depth: number,
    routeIndex?: number
  ): void {
    if (depth > PARSER_LIMITS.MAX_ROUTER_DEPTH) {
      throw new Error(
        `Blueprint exceeds maximum router nesting depth (${PARSER_LIMITS.MAX_ROUTER_DEPTH}).`
      );
    }

    let previousId: string | null = parentId;

    for (let i = 0; i < flow.length; i++) {
      const candidate = flow[i];
      if (!isValidMakeModule(candidate)) {
        parseWarnings.push(`Skipped malformed module at depth ${depth}, index ${i}.`);
        continue;
      }

      const id = String(candidate.id);
      if (Object.prototype.hasOwnProperty.call(nodes, id)) {
        parseWarnings.push(`Duplicate module ID #${id} encountered; skipping duplicate definition.`);
        continue;
      }

      nodeCount += 1;
      if (nodeCount > PARSER_LIMITS.MAX_NODES) {
        throw new Error(
          `Blueprint exceeds maximum supported module count (${PARSER_LIMITS.MAX_NODES}).`
        );
      }

      const { url: targetUrl, hostname } = extractSafeTargetUrl(candidate, parseWarnings);
      const ai = classifyAI(candidate, targetUrl, hostname, allowedGateways);
      const roles = classifyRoles(candidate, ai);

      const refs = new Set<string>();
      extractIMLReferences(candidate.mapper, refs);
      extractIMLReferences(candidate.parameters, refs);
      extractIMLReferences(candidate.filter, refs);
      refs.delete(id);

      nodes[id] = {
        id,
        platform: 'make',
        rawType: candidate.module,
        label: formatLabel(candidate),
        roles,
        ai,
        egressUrl: targetUrl,
        referencedNodeIds: Array.from(refs),
        branchDepth: depth,
        hasFilter: hasFilterConditions(candidate),
      };

      if (previousId === null) {
        entryNodeIds.push(id);
      } else {
        edges.push({
          from: previousId,
          to: id,
          kind: 'control_flow',
          ...(i === 0 && routeIndex !== undefined ? { routeIndex } : {}),
        });
      }

      // Walk nested router branches
      if (Array.isArray(candidate.routes) && candidate.routes.length > 0) {
        candidate.routes.forEach((route, idx) => {
          if (isPlainRecord(route) && Array.isArray(route.flow) && route.flow.length > 0) {
            walkFlow(route.flow, id, depth + 1, idx);
          }
        });
      }

      // Walk Make.com error-handler branches (onerror)
      if (Array.isArray(candidate.onerror) && candidate.onerror.length > 0) {
        walkFlow(candidate.onerror, id, depth + 1);
      }

      previousId = id;
    }
  }

  walkFlow(raw.flow, null, 0);

  // Build explicit data-flow edges from Make IML references once all nodes exist
  const edgeKeys = new Set(edges.map((e) => `${e.from}->${e.to}:${e.kind}`));
  for (const node of Object.values(nodes)) {
    for (const refId of node.referencedNodeIds) {
      if (!Object.prototype.hasOwnProperty.call(nodes, refId)) {
        parseWarnings.push(
          `Module #${node.id} references unknown module ID #${refId} in IML expression.`
        );
        continue;
      }
      const key = `${refId}->${node.id}:data_flow`;
      if (!edgeKeys.has(key)) {
        edgeKeys.add(key);
        edges.push({ from: refId, to: node.id, kind: 'data_flow' });
      }
    }
  }

  const blueprintName =
    typeof raw.name === 'string' && raw.name.trim().length > 0
      ? raw.name.trim().slice(0, 120)
      : 'Untitled Make Scenario';

  return {
    platform: 'make',
    name: blueprintName,
    nodes,
    edges,
    entryNodeIds,
    parseWarnings,
  };
}
