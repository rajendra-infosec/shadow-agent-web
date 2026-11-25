function redactSensitivePath(pathname: string): string {
  if (!pathname || pathname === '/') return pathname;
  const p = pathname
    .replace(/\/services\/[^/?#]+(?:\/[^/?#]+)*/gi, '/services/[REDACTED]')
    .replace(/\/api\/webhooks\/[^/?#]+(?:\/[^/?#]+)*/gi, '/api/webhooks/[REDACTED]')
    .replace(/\/bot[0-9]{5,}:[A-Za-z0-9_-]+/gi, '/bot[REDACTED]');

  return p
    .split('/')
    .map((seg) => {
      if (!seg || seg.includes('{{') || seg.startsWith('[REDACTED')) return seg;
      if (seg.length >= 20 && /^[A-Za-z0-9_.:-]+$/.test(seg)) {
        return '[REDACTED_TOKEN]';
      }
      return seg;
    })
    .join('/');
}

import type {
  AINodeMetadata,
  AnalysisStatus,
  IREdge,
  IRNode,
  NodeSecurityRole,
  WorkflowIR,
} from '../types/workflowIR';

export const PARSER_LIMITS = {
  MAX_INPUT_BYTES: 5 * 1024 * 1024, // 5 MB
  MAX_ROUTER_DEPTH: 32,
  MAX_OBJECT_DEPTH: 40,
  MAX_MODULES: 2_000,
  MAX_STRING_SCAN_CHARS: 50_000,
  MAX_IML_BLOCKS_PER_STRING: 500,
} as const;

export interface MakeParseOptions {
  allowedGatewayHosts?: string[];
}

const DEFAULT_GATEWAY_HOSTS = [
  'gateway.ai.cloudflare.com',
  'api.portkey.ai',
];

const VENDOR_LLM_HOSTS: Record<string, string> = {
  'api.openai.com': 'openai',
  'api.anthropic.com': 'anthropic',
  'generativelanguage.googleapis.com': 'google',
  'api.cohere.ai': 'cohere',
  'api.cohere.com': 'cohere',
  'api.mistral.ai': 'mistral',
  'api.groq.com': 'groq',
  'api.together.xyz': 'together',
  'api.perplexity.ai': 'perplexity',
};

const NATIVE_LLM_PREFIXES: Array<{ prefix: string; provider: string }> = [
  { prefix: 'openai', provider: 'openai' },
  { prefix: 'anthropic', provider: 'anthropic' },
  { prefix: 'google-gemini', provider: 'google' },
  { prefix: 'google-vertex-ai', provider: 'google' },
  { prefix: 'cohere', provider: 'cohere' },
  { prefix: 'mistral', provider: 'mistral' },
  { prefix: 'groq', provider: 'groq' },
  { prefix: 'perplexity', provider: 'perplexity' },
  { prefix: 'huggingface', provider: 'huggingface' },
  { prefix: 'langchain', provider: 'langchain' },
];

const UNTRUSTED_SOURCE_PREFIXES = [
  'gateway:customwebhook',
  'gateway:custommailhook',
  'google-email:watch',
  'email:watch',
  'slack:watch',
  'telegram:watch',
  'discord:watch',
  'typeform:watch',
  'google-forms:watch',
  'tally:watch',
  'airtable:watch',
  'google-sheets:watch',
  'notion:watch',
  'hubspot:watch',
  'salesforce:watch',
  'zendesk:watch',
  'intercom:watch',
  'jira:watch',
  'github:watch',
  'rss:watch',
  'http:actiongetdata',
];

const OUTBOUND_SINK_PREFIXES = [
  'http:actionsenddata',
  'http:makearequest',
  'http:actionrequest',
  'google-email:actionsendemail',
  'email:actionsendemail',
  'slack:createmessage',
  'slack:postmessage',
  'telegram:sendmessage',
  'discord:sendmessage',
  'gmail:sendemail',
  'twilio:sendmessage',
  'hubspot:create',
  'hubspot:update',
  'salesforce:create',
  'salesforce:update',
  'airtable:create',
  'airtable:update',
  'google-sheets:addrow',
  'google-sheets:updaterow',
  'notion:create',
  'notion:update',
  'github:createissue',
  'jira:createissue',
  'gateway:webhookrespond',
];

const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

interface ParseState {
  warnings: string[];
  partial: boolean;
  moduleCount: number;
  seenNodeIds: Set<string>;
}

function flagPartial(state: ParseState, reason: string): void {
  state.partial = true;
  if (!state.warnings.includes(reason)) {
    state.warnings.push(reason);
  }
}

/**
 * Prototype-pollution-safe JSON reviver.
 */
function safeJsonParse(raw: string): unknown {
  return JSON.parse(raw, (key, value) => {
    if (DANGEROUS_KEYS.has(key)) {
      return undefined;
    }
    return value;
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Linear-time O(n) IML reference extractor (`{{12.body}}`, `{{3.choices[].text}}`).
 * Bounded against ReDoS and pathological brace bombs; flags PARTIAL if truncated.
 */
function stripQuotedStrings(expr: string): string {
  let out = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
        out += ' ';
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ' ';
      continue;
    }
    out += ch;
  }

  return out;
}

function extractImlRefsFromString(input: string, state: ParseState): string[] {
  const refs = new Set<string>();
  let limit = input.length;
  if (limit > PARSER_LIMITS.MAX_STRING_SCAN_CHARS) {
    limit = PARSER_LIMITS.MAX_STRING_SCAN_CHARS;
    flagPartial(
      state,
      `String exceeded ${PARSER_LIMITS.MAX_STRING_SCAN_CHARS} character scan limit; trailing content was not inspected.`
    );
  }

  let cursor = 0;
  let blocksScanned = 0;
  const refRegex = /(?:^|[^A-Za-z0-9_$.])(\d+)\.[A-Za-z0-9_]/g;

  while (cursor < limit) {
    const openIdx = input.indexOf('{{', cursor);
    if (openIdx === -1 || openIdx >= limit) break;

    blocksScanned++;
    if (blocksScanned > PARSER_LIMITS.MAX_IML_BLOCKS_PER_STRING) {
      flagPartial(
        state,
        `Mapping expression exceeded ${PARSER_LIMITS.MAX_IML_BLOCKS_PER_STRING} IML block limit; remaining references were not inspected.`
      );
      break;
    }

    const closeIdx = input.indexOf('}}', openIdx + 2);
    if (closeIdx === -1 || closeIdx >= limit) break;

    const expr = stripQuotedStrings(input.slice(openIdx + 2, closeIdx));
    refRegex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = refRegex.exec(expr)) !== null) {
      refs.add(match[1]);
    }

    cursor = closeIdx + 2;
  }

  return Array.from(refs);
}

function collectImlRefsDeep(
  value: unknown,
  state: ParseState,
  depth = 0,
  acc = new Set<string>()
): Set<string> {
  if (depth > PARSER_LIMITS.MAX_OBJECT_DEPTH) {
    flagPartial(
      state,
      `Nested module configuration exceeded ${PARSER_LIMITS.MAX_OBJECT_DEPTH} levels; deeper fields were skipped.`
    );
    return acc;
  }

  if (typeof value === 'string') {
    for (const ref of extractImlRefsFromString(value, state)) {
      acc.add(ref);
    }
    return acc;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectImlRefsDeep(item, state, depth + 1, acc);
    }
    return acc;
  }

  if (isPlainRecord(value)) {
    for (const key of Object.keys(value)) {
      if (DANGEROUS_KEYS.has(key)) continue;
      collectImlRefsDeep(value[key], state, depth + 1, acc);
    }
  }

  return acc;
}

interface AnalyzedUrl {
  validHttp: boolean;
  redactedUrl?: string;
  protocol?: string;
  hostname?: string;
  hasDynamicHost: boolean;
  hasDynamicPathOrQuery: boolean;
  urlReferencedNodeIds: string[];
}

/**
 * Inspects an HTTP target URL without trusting regex-only host matching.
 * - Rejects non-HTTP(S) schemes (e.g., javascript:, file:, data:).
 * - Distinguishes {{...}} in authority/hostname (SSRF) vs path/query.
 * - Redacts credentials, query parameter values, and fragments before storage/export.
 */
function inspectAndRedactUrl(rawUrl: string, state: ParseState): AnalyzedUrl {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return {
      validHttp: false,
      hasDynamicHost: false,
      hasDynamicPathOrQuery: false,
      urlReferencedNodeIds: [],
    };
  }

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(trimmed);
  if (!schemeMatch) {
    if (trimmed.startsWith('{{')) {
      const refs = extractImlRefsFromString(trimmed, state);
      const slashIdx = trimmed.indexOf('/');
      const queryIdx = trimmed.indexOf('?');
      const cutCandidates = [slashIdx, queryIdx].filter((i) => i !== -1);
      const pathStart = cutCandidates.length > 0 ? Math.min(...cutCandidates) : trimmed.length;
      const hostPart = trimmed.slice(0, pathStart);
      return {
        validHttp: true,
        redactedUrl: `${hostPart}/[REDACTED_PATH_AND_QUERY]`,
        hasDynamicHost: true,
        hasDynamicPathOrQuery: pathStart < trimmed.length,
        urlReferencedNodeIds: refs,
      };
    }

    return {
      validHttp: false,
      hasDynamicHost: false,
      hasDynamicPathOrQuery: false,
      urlReferencedNodeIds: [],
    };
  }

  const protocol = `${schemeMatch[1].toLowerCase()}:`;
  if (protocol !== 'http:' && protocol !== 'https:') {
    return {
      validHttp: false,
      hasDynamicHost: false,
      hasDynamicPathOrQuery: false,
      urlReferencedNodeIds: [],
    };
  }

  const afterScheme = trimmed.slice(schemeMatch[0].length);
  const pathStartCandidates = [
    afterScheme.indexOf('/'),
    afterScheme.indexOf('?'),
    afterScheme.indexOf('#'),
  ].filter((idx) => idx !== -1);

  const authorityEnd =
    pathStartCandidates.length > 0 ? Math.min(...pathStartCandidates) : afterScheme.length;

  const rawAuthority = afterScheme.slice(0, authorityEnd);
  const rawRest = afterScheme.slice(authorityEnd);

  const allUrlRefs = extractImlRefsFromString(trimmed, state);
  const atIdxEarly = rawAuthority.lastIndexOf('@');
  const hostPortOnly = atIdxEarly !== -1 ? rawAuthority.slice(atIdxEarly + 1) : rawAuthority;
  const hasDynamicHost = hostPortOnly.includes('{{');
  const hasDynamicPathOrQuery = rawRest.includes('{{');

  const atIdx = rawAuthority.lastIndexOf('@');
  const cleanAuthority = atIdx !== -1 ? rawAuthority.slice(atIdx + 1) : rawAuthority;

  if (hasDynamicHost) {
    const queryIdx = rawRest.indexOf('?');
    const hashIdx = rawRest.indexOf('#');
    let pathOnly = rawRest;
    let hasQuery = false;

    if (queryIdx !== -1 && (hashIdx === -1 || queryIdx < hashIdx)) {
      pathOnly = rawRest.slice(0, queryIdx);
      hasQuery = true;
    } else if (hashIdx !== -1) {
      pathOnly = rawRest.slice(0, hashIdx);
    }

    const redactedUrl = `${protocol}//${cleanAuthority}${redactSensitivePath(pathOnly)}${hasQuery ? '?[REDACTED]' : ''}`;
    return {
      validHttp: true,
      redactedUrl,
      protocol,
      hasDynamicHost: true,
      hasDynamicPathOrQuery,
      urlReferencedNodeIds: allUrlRefs,
    };
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        validHttp: false,
        hasDynamicHost: false,
        hasDynamicPathOrQuery: false,
        urlReferencedNodeIds: [],
      };
    }

    const redactedParams: string[] = [];
    parsed.searchParams.forEach((_val, key) => {
      redactedParams.push(`${encodeURIComponent(key)}=[REDACTED]`);
    });

    const querySuffix = redactedParams.length > 0 ? `?${redactedParams.join('&')}` : '';
    const redactedUrl = `${parsed.protocol}//${parsed.host}${redactSensitivePath(parsed.pathname)}${querySuffix}`;

    return {
      validHttp: true,
      redactedUrl,
      protocol: parsed.protocol,
      hostname: parsed.hostname.toLowerCase(),
      hasDynamicHost: false,
      hasDynamicPathOrQuery,
      urlReferencedNodeIds: allUrlRefs,
    };
  } catch {
    return {
      validHttp: false,
      hasDynamicHost: false,
      hasDynamicPathOrQuery: false,
      urlReferencedNodeIds: [],
    };
  }
}

function extractUrlCandidate(moduleObj: Record<string, unknown>): string | undefined {
  const mapper = isPlainRecord(moduleObj.mapper) ? moduleObj.mapper : undefined;
  const parameters = isPlainRecord(moduleObj.parameters) ? moduleObj.parameters : undefined;

  const candidates = [
    mapper?.url,
    mapper?.uri,
    mapper?.endpoint,
    parameters?.url,
    parameters?.uri,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }
  return undefined;
}

function classifyAIAndRoles(
  rawType: string,
  analyzedUrl: AnalyzedUrl | undefined,
  allowedGatewayHosts: Set<string>
): { roles: NodeSecurityRole[]; ai: AINodeMetadata } {
  const lowerType = rawType.toLowerCase();
  const roles = new Set<NodeSecurityRole>();

  if (lowerType.includes('router')) {
    roles.add('router');
  }

  if (UNTRUSTED_SOURCE_PREFIXES.some((prefix) => lowerType.startsWith(prefix))) {
    roles.add('untrusted_source');
  }

  const nativeMatch = NATIVE_LLM_PREFIXES.find((entry) => lowerType.startsWith(entry.prefix));
  if (nativeMatch) {
    roles.add('llm_processor');
    return {
      roles: Array.from(roles),
      ai: {
        isLLM: true,
        provider: nativeMatch.provider,
        gatewayStatus: 'native_bypass',
      },
    };
  }

  if (lowerType.startsWith('http:') && analyzedUrl?.validHttp) {
    if (
      !analyzedUrl.hasDynamicHost &&
      analyzedUrl.protocol === 'https:' &&
      analyzedUrl.hostname &&
      allowedGatewayHosts.has(analyzedUrl.hostname)
    ) {
      roles.add('llm_processor');
      return {
        roles: Array.from(roles),
        ai: {
          isLLM: true,
          provider: 'gateway',
          gatewayStatus: 'gateway_routed',
          targetUrl: analyzedUrl.redactedUrl,
        },
      };
    }

    if (
      !analyzedUrl.hasDynamicHost &&
      analyzedUrl.hostname &&
      Object.prototype.hasOwnProperty.call(VENDOR_LLM_HOSTS, analyzedUrl.hostname)
    ) {
      roles.add('llm_processor');
      return {
        roles: Array.from(roles),
        ai: {
          isLLM: true,
          provider: VENDOR_LLM_HOSTS[analyzedUrl.hostname],
          gatewayStatus: 'direct_http_bypass',
          targetUrl: analyzedUrl.redactedUrl,
        },
      };
    }
  }

  if (OUTBOUND_SINK_PREFIXES.some((prefix) => lowerType.startsWith(prefix))) {
    roles.add('outbound_sink');
  }

  if (roles.size === 0) {
    roles.add('transform');
  }

  return {
    roles: Array.from(roles),
    ai: {
      isLLM: false,
      gatewayStatus: 'none',
    },
  };
}

function extractDesignerLabel(moduleObj: Record<string, unknown>, id: string, rawType: string): string {
  const metadata = isPlainRecord(moduleObj.metadata) ? moduleObj.metadata : undefined;
  const designer = metadata && isPlainRecord(metadata.designer) ? metadata.designer : undefined;
  const name = typeof designer?.name === 'string' ? designer.name.trim() : '';
  return name ? `${name} (#${id})` : `${rawType} (#${id})`;
}

export function parseMakeBlueprint(
  input: string | Record<string, unknown>,
  options: MakeParseOptions = {}
): WorkflowIR {
  let root: unknown;

  if (typeof input === 'string') {
    if (input.length > PARSER_LIMITS.MAX_INPUT_BYTES) {
      throw new Error(
        `Blueprint exceeds ${PARSER_LIMITS.MAX_INPUT_BYTES / (1024 * 1024)} MB safety ceiling.`
      );
    }
    root = safeJsonParse(input);
  } else {
    root = input;
  }

  if (!isPlainRecord(root) || !Array.isArray(root.flow)) {
    throw new Error('Invalid Make.com blueprint: missing top-level "flow" array.');
  }

  const allowedGatewayHosts = new Set<string>(DEFAULT_GATEWAY_HOSTS);
  for (const host of options.allowedGatewayHosts ?? []) {
    const normalized = host.trim().toLowerCase();
    if (normalized) {
      allowedGatewayHosts.add(normalized);
    }
  }

  const state: ParseState = {
    warnings: [],
    partial: false,
    moduleCount: 0,
    seenNodeIds: new Set<string>(),
  };

  const nodes: Record<string, IRNode> = {};
  const edges: IREdge[] = [];
  const entryNodeIds: string[] = [];

  function walkFlow(
    flowArray: unknown[],
    upstreamIds: string[],
    branchDepth: number,
    isErrorHandler = false,
    routeIndex?: number
  ): string[] {
    if (branchDepth > PARSER_LIMITS.MAX_ROUTER_DEPTH) {
      throw new Error(
        `Maximum router nesting depth (${PARSER_LIMITS.MAX_ROUTER_DEPTH}) exceeded.`
      );
    }

    let currentUpstream = [...upstreamIds];

    for (const rawItem of flowArray) {
      if (!isPlainRecord(rawItem)) continue;

      state.moduleCount++;
      if (state.moduleCount > PARSER_LIMITS.MAX_MODULES) {
        flagPartial(
          state,
          `Blueprint exceeded ${PARSER_LIMITS.MAX_MODULES} module safety limit; remaining modules were not inspected.`
        );
        break;
      }

      const rawId = rawItem.id;
      const id =
        typeof rawId === 'number' || typeof rawId === 'string'
          ? String(rawId).trim()
          : `anon_${state.moduleCount}`;

      if (!id || DANGEROUS_KEYS.has(id)) continue;

      if (state.seenNodeIds.has(id)) {
        flagPartial(
          state,
          `Duplicate module ID "#${id}" detected; graph edges for duplicate IDs may be ambiguous.`
        );
      }
      state.seenNodeIds.add(id);

      const rawType =
        typeof rawItem.module === 'string' && rawItem.module.trim()
          ? rawItem.module.trim()
          : 'unknown:Module';

      const rawUrl = extractUrlCandidate(rawItem);
      let analyzedUrl: AnalyzedUrl | undefined;

      if (rawUrl !== undefined) {
        analyzedUrl = inspectAndRedactUrl(rawUrl, state);
        if (!analyzedUrl.validHttp && rawType.toLowerCase().startsWith('http:')) {
          state.warnings.push(
            `Rejected non-HTTP(S) or malformed URI scheme in module #${id} (${rawType}).`
          );
        }
      }

      const { roles, ai } = classifyAIAndRoles(rawType, analyzedUrl, allowedGatewayHosts);
      const label = extractDesignerLabel(rawItem, id, rawType);
      const hasFilter = isPlainRecord(rawItem.filter);

      const refs = collectImlRefsDeep(
        {
          mapper: rawItem.mapper,
          parameters: rawItem.parameters,
        },
        state
      );
      refs.delete(id);

      const urlRefs = (analyzedUrl?.urlReferencedNodeIds ?? []).filter((refId) => refId !== id);

      const node: IRNode = {
        id,
        platform: 'make',
        rawType,
        label,
        roles,
        ai,
        egressUrl: analyzedUrl?.validHttp ? analyzedUrl.redactedUrl : undefined,
        egressUrlHasDynamicHost: analyzedUrl?.validHttp ? analyzedUrl.hasDynamicHost : undefined,
        egressUrlHasDynamicPathOrQuery: analyzedUrl?.validHttp
          ? analyzedUrl.hasDynamicPathOrQuery
          : undefined,
        urlReferencedNodeIds: urlRefs.length > 0 ? urlRefs : undefined,
        referencedNodeIds: Array.from(refs),
        branchDepth,
        hasFilter,
      };

      nodes[id] = node;

      if (currentUpstream.length === 0) {
        if (!entryNodeIds.includes(id)) {
          entryNodeIds.push(id);
        }
      } else {
        for (const prevId of currentUpstream) {
          edges.push({
            from: prevId,
            to: id,
            kind: 'control_flow',
            routeIndex,
            isErrorHandler,
          });
        }
      }

      for (const refId of node.referencedNodeIds) {
        edges.push({
          from: refId,
          to: id,
          kind: 'data_flow',
        });
      }

      if (Array.isArray(rawItem.onerror)) {
        walkFlow(rawItem.onerror, [id], branchDepth + 1, true);
      }

      if (Array.isArray(rawItem.routes)) {
        const branchTails: string[] = [];
        rawItem.routes.forEach((routeObj, idx) => {
          if (isPlainRecord(routeObj) && Array.isArray(routeObj.flow)) {
            const tails = walkFlow(routeObj.flow, [id], branchDepth + 1, isErrorHandler, idx);
            branchTails.push(...tails);
          }
        });
        currentUpstream = branchTails.length > 0 ? branchTails : [id];
      } else {
        currentUpstream = [id];
      }
    }

    return currentUpstream;
  }

  walkFlow(root.flow, [], 0, false);

  const workflowName =
    typeof root.name === 'string' && root.name.trim()
      ? root.name.trim()
      : 'Untitled Make.com Blueprint';

  const analysisStatus: AnalysisStatus = state.partial ? 'PARTIAL' : 'COMPLETE';

  return {
    platform: 'make',
    name: workflowName,
    analysisStatus,
    nodes,
    edges,
    entryNodeIds,
    parseWarnings: state.warnings,
  };
}