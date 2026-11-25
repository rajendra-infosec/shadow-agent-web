import { describe, expect, it } from 'vitest';
import { PARSER_LIMITS, parseMakeBlueprint } from '../src/adapters/makeAdapter';
import { analyzeWorkflow } from '../src/engine/taintEngine';

describe('taintEngine static analyzer', () => {
  it('flags explicit Input -> LLM -> Outbound mapping chain and native connector', () => {
    const ir = parseMakeBlueprint({
      name: 'Contract Leak PoC',
      flow: [
        { id: 1, module: 'google-email:WatchEmails' },
        {
          id: 2,
          module: 'openai-gpt-3:CreateCompletion',
          mapper: { prompt: 'Reply to {{1.text}}' },
        },
        {
          id: 3,
          module: 'google-email:ActionSendEmail',
          mapper: { content: '{{2.choices[].message.content}}' },
        },
      ],
    });

    const report = analyzeWorkflow(ir);
    expect(report.summary.verdict).toBe('REVIEW_REQUIRED');
    expect(report.findings.some((f) => f.ruleId === 'CANDIDATE_TRIFECTA_CHAIN' && f.severity === 'HIGH')).toBe(true);
    expect(report.findings.some((f) => f.ruleId === 'NATIVE_LLM_CONNECTOR_OBSERVED')).toBe(true);
  });

  it('does NOT flag SSRF for a fixed hostname with a dynamic query parameter', () => {
    const ir = parseMakeBlueprint({
      name: 'Fixed Host Dynamic Query',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: {
            url: 'https://hooks.example.com/notify?target={{1.callback}}&token=secret123',
          },
        },
      ],
    });

    const report = analyzeWorkflow(ir);
    expect(report.findings.some((f) => f.ruleId === 'TAINTED_DYNAMIC_HOST')).toBe(false);
    expect(ir.nodes['2'].egressUrl).not.toContain('secret123');
  });

  it('flags HIGH TAINTED_DYNAMIC_HOST when untrusted input controls the destination hostname', () => {
    const ir = parseMakeBlueprint({
      name: 'Dynamic Host SSRF',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: {
            url: 'https://{{1.tenantHost}}/ingest?api_key=sk_secret_999',
          },
        },
      ],
    });

    const report = analyzeWorkflow(ir);
    const ssrf = report.findings.find((f) => f.ruleId === 'TAINTED_DYNAMIC_HOST');
    expect(ssrf).toBeDefined();
    expect(ssrf?.severity).toBe('HIGH');
    expect(ssrf?.description).not.toContain('sk_secret_999');
  });

  it('detects direct HTTP calls to vendor LLM endpoints', () => {
    const ir = parseMakeBlueprint({
      name: 'Direct OpenAI HTTP',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: {
            url: 'https://api.openai.com/v1/chat/completions',
            body: '{{1.text}}',
          },
        },
      ],
    });

    const report = analyzeWorkflow(ir);
    expect(report.findings.some((f) => f.ruleId === 'DIRECT_PROVIDER_ENDPOINT_DECLARED')).toBe(true);
  });

  it('returns NO_CANDIDATES_FOUND on isolated parallel router branches using an allowlisted gateway', () => {
    const ir = parseMakeBlueprint({
      name: 'Isolated Gateway Workflow',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'builtin:BasicRouter',
          routes: [
            {
              flow: [
                {
                  id: 3,
                  module: 'http:ActionSendData',
                  mapper: {
                    url: 'https://gateway.ai.cloudflare.com/v1/org/gw/openai/chat/completions',
                    body: '{{1.ticket}}',
                  },
                },
              ],
            },
            {
              flow: [
                {
                  id: 4,
                  module: 'slack:CreateMessage',
                  mapper: { text: 'Static counter notification' },
                },
              ],
            },
          ],
        },
      ],
    });

    const report = analyzeWorkflow(ir);
    expect(report.summary.verdict).toBe('NO_CANDIDATES_FOUND');
    expect(report.summary.gatewayHostMatchedCount).toBe(1);
    expect(report.findings).toHaveLength(0);
  });

  it('never returns NO_CANDIDATES_FOUND when analysisStatus is PARTIAL', () => {
    const oversized = 'X'.repeat(PARSER_LIMITS.MAX_STRING_SCAN_CHARS + 100);
    const ir = parseMakeBlueprint({
      name: 'Truncated Safe-Looking Flow',
      flow: [
        { id: 1, module: 'json:ParseJSON', mapper: { blob: oversized } },
      ],
    });

    const report = analyzeWorkflow(ir);
    expect(report.analysisStatus).toBe('PARTIAL');
    expect(report.summary.verdict).toBe('INCOMPLETE_ANALYSIS');
  });

  it('tracks onerror fallback sinks', () => {
    const ir = parseMakeBlueprint({
      name: 'OnError Egress',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'openai-gpt-3:CreateCompletion',
          mapper: { prompt: '{{1.body}}' },
          onerror: [
            {
              id: 3,
              module: 'slack:CreateMessage',
              mapper: { text: 'Failed on: {{2.choices[].message.content}}' },
            },
          ],
        },
      ],
    });

    const report = analyzeWorkflow(ir);
    expect(report.findings.some((f) => f.ruleId === 'CANDIDATE_TRIFECTA_CHAIN')).toBe(true);
  });
  it("redacts path-embedded webhook secrets (Slack, Discord, Telegram, Make) via canary check", () => {
    const canaries = [
      "CANARY_SLACK_SECRET_999",
      "CANARY_DISCORD_TOKEN_888",
      "987654321:CANARY_TG_BOT_777",
      "canarymaketoken1234567890abcdef",
    ];
    const ir = parseMakeBlueprint({
      name: "Webhook Path Canary",
      flow: [
        { id: 1, module: "http:ActionSendData", mapper: { url: "https://hooks.slack.com/services/T000/B000/CANARY_SLACK_SECRET_999" } },
        { id: 2, module: "http:ActionSendData", mapper: { url: "https://discord.com/api/webhooks/12345/CANARY_DISCORD_TOKEN_888" } },
        { id: 3, module: "http:ActionSendData", mapper: { url: "https://api.telegram.org/bot987654321:CANARY_TG_BOT_777/sendMessage" } },
        { id: 4, module: "http:ActionSendData", mapper: { url: "https://hook.eu1.make.com/canarymaketoken1234567890abcdef" } },
      ],
    });
    const serialized = JSON.stringify(ir);
    for (const canary of canaries) {
      expect(serialized).not.toContain(canary);
    }
  });
  it('extracts module refs wrapped inside IML functions (e.g., trim, lower, replace)', () => {
    const ir = parseMakeBlueprint({
      name: 'Wrapped IML Functions',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        { id: 2, module: 'openai-gpt-3:CreateCompletion', mapper: { prompt: '{{trim(1.body)}}' } },
        { id: 3, module: 'http:ActionSendData', mapper: { url: 'https://{{lower(1.host)}}/exfil', data: '{{replace(2.result; "a"; "b")}}' } },
      ],
    });
    const report = analyzeWorkflow(ir);
    expect(report.findings.some((f) => f.ruleId === 'CANDIDATE_TRIFECTA_CHAIN' && f.severity === 'HIGH')).toBe(true);
    expect(report.findings.some((f) => f.ruleId === 'TAINTED_DYNAMIC_HOST' && f.severity === 'HIGH')).toBe(true);
  });

  it('does NOT promote filter-only references to HIGH explicit data-flow chains', () => {
    const ir = parseMakeBlueprint({
      name: 'Filter Only Reference',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        { id: 2, module: 'openai-gpt-3:CreateCompletion', filter: { conditions: [[{ a: '{{1.flag}}', b: 'yes' }]] }, mapper: { prompt: 'Static prompt' } },
        { id: 3, module: 'http:ActionSendData', filter: { conditions: [[{ a: '{{2.status}}', b: 'ok' }]] }, mapper: { url: 'https://example.com/notify', data: 'Static alert' } },
      ],
    });
    const report = analyzeWorkflow(ir);
    const chain = report.findings.find((f) => f.ruleId === 'CANDIDATE_TRIFECTA_CHAIN');
    expect(chain?.severity).toBe('LOW');
    expect(chain?.evidenceBasis).toBe('control_flow_only');
  });

  it('does NOT flag dynamic URL userinfo@ on a fixed hostname as TAINTED_DYNAMIC_HOST', () => {
    const ir = parseMakeBlueprint({
      name: 'Dynamic Userinfo Fixed Host',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        { id: 2, module: 'http:ActionSendData', mapper: { url: 'https://{{1.username}}@fixed.example.com/callback' } },
      ],
    });
    const report = analyzeWorkflow(ir);
    expect(report.findings.some((f) => f.ruleId === 'TAINTED_DYNAMIC_HOST')).toBe(false);
  });
  it('ignores reference-shaped text inside quoted IML string literals (including escaped quotes)', () => {
    const ir = parseMakeBlueprint({
      name: 'Quoted IML Literals',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        { id: 2, module: 'openai-gpt-3:CreateCompletion', mapper: { prompt: 'static' } },
        {
          id: 3,
          module: 'http:ActionSendData',
          mapper: {
            url: 'https://example.com/hook',
            data: '{{replace(1.body; "literal 2.body \\"2.secret\\""; \'2.other\')}}',
          },
        },
      ],
    });
    expect(ir.nodes['3'].referencedNodeIds).toContain('1');
    expect(ir.nodes['3'].referencedNodeIds).not.toContain('2');
  });

  it('fails closed to INCOMPLETE_ANALYSIS when global MAX_TOTAL_BFS_VISITS budget is exhausted', () => {
    const nodes: Record<string, any> = {};
    const edges: any[] = [];

    // 100-node unreachable chain
    for (let i = 0; i < 100; i++) {
      const id = `c${i}`;
      nodes[id] = {
        id,
        platform: 'make',
        rawType: 'util:SetVariable',
        label: `Chain ${i}`,
        roles: ['neutral'],
        ai: { isLLM: false, gatewayStatus: 'none' },
        referencedNodeIds: [],
        branchDepth: 0,
        hasFilter: false,
      };
      if (i > 0) {
        edges.push({ from: `c${i - 1}`, to: id, kind: 'control_flow', isErrorHandler: false });
      }
    }

    // 100 untrusted sources feeding into the 100-node chain
    for (let i = 0; i < 100; i++) {
      const id = `s${i}`;
      nodes[id] = {
        id,
        platform: 'make',
        rawType: 'gateway:CustomWebHook',
        label: `Source ${i}`,
        roles: ['untrusted_source'],
        ai: { isLLM: false, gatewayStatus: 'none' },
        referencedNodeIds: [],
        branchDepth: 0,
        hasFilter: false,
      };
      edges.push({ from: id, to: 'c0', kind: 'control_flow', isErrorHandler: false });
    }

    // 10 disconnected gateway-routed LLMs (100 * 10 * ~101 visits > 50,000 global budget, 0 findings)
    for (let i = 0; i < 10; i++) {
      const id = `l${i}`;
      nodes[id] = {
        id,
        platform: 'make',
        rawType: 'http:ActionSendData',
        label: `LLM ${i}`,
        roles: ['llm_processor'],
        ai: { isLLM: true, provider: 'openai', gatewayStatus: 'gateway_routed' },
        referencedNodeIds: [],
        branchDepth: 0,
        hasFilter: false,
      };
    }

    const report = analyzeWorkflow({
      platform: 'make',
      name: 'Global BFS Budget Exhaustion',
      analysisStatus: 'COMPLETE',
      nodes,
      edges,
      entryNodeIds: ['s0'],
      parseWarnings: [],
    });

    expect(report.analysisStatus).toBe('PARTIAL');
    expect(report.summary.verdict).toBe('INCOMPLETE_ANALYSIS');
    expect(report.summary.verdict).not.toBe('NO_CANDIDATES_FOUND');
  });
});
