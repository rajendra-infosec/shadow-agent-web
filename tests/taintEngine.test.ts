import { describe, expect, it } from 'vitest';
import { parseMakeBlueprint } from '../src/adapters/makeAdapter';
import { analyzeWorkflow, ENGINE_LIMITS } from '../src/engine/taintEngine';
import type { WorkflowIR } from '../src/types/workflowIR';

describe('taintEngine — detection accuracy', () => {
  it('flags Confirmed Lethal Trifecta (CRITICAL) and Native Gateway Bypass (HIGH) across nested routers', () => {
    const blueprint = {
      name: 'Customer Support Auto-Responder',
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
                  module: 'openai-gpt-3:CreateCompletion',
                  mapper: { prompt: 'Summarize ticket: {{1.body}}' },
                },
                {
                  id: 4,
                  module: 'google-email:ActionSendEmail',
                  mapper: {
                    to: '{{1.replyTo}}',
                    content: '{{3.choices[].message.content}}',
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const report = analyzeWorkflow(parseMakeBlueprint(blueprint));

    expect(report.summary.verdict).toBe('CRITICAL');
    expect(report.summary.criticalCount).toBe(1);
    expect(report.summary.gatewayBypassCount).toBe(1);

    const trifecta = report.findings.find((f) => f.ruleId === 'LETHAL_TRIFECTA');
    expect(trifecta).toBeDefined();
    expect(trifecta?.severity).toBe('CRITICAL');
    expect(trifecta?.confidence).toBe('confirmed');
    expect(trifecta?.pathNodeIds).toEqual(['1', '3', '4']);

    const bypass = report.findings.find((f) => f.ruleId === 'SHADOW_AI_NATIVE_BYPASS');
    expect(bypass).toBeDefined();
    expect(bypass?.severity).toBe('HIGH');
  });

  it('produces ZERO Lethal Trifecta false positives when LLM and Sink live on isolated parallel router branches', () => {
    const blueprint = {
      name: 'Isolated Parallel Branches',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'builtin:BasicRouter',
          routes: [
            {
              // Route A: Gateway-routed LLM only (no egress sink)
              flow: [
                {
                  id: 3,
                  module: 'http:ActionSendData',
                  mapper: {
                    url: 'https://gateway.ai.cloudflare.com/v1/acc/gw/openai',
                    data: '{{1.body}}',
                  },
                },
              ],
            },
            {
              // Route B: Static Slack alert only (never touches LLM #3)
              flow: [
                {
                  id: 4,
                  module: 'slack:CreateMessage',
                  mapper: { text: 'New webhook received' },
                },
              ],
            },
          ],
        },
      ],
    };

    const report = analyzeWorkflow(parseMakeBlueprint(blueprint));

    expect(report.findings.some((f) => f.ruleId === 'LETHAL_TRIFECTA')).toBe(false);
    expect(report.summary.verdict).toBe('CLEAN');
    expect(report.summary.gatewayRoutedCount).toBe(1);
  });

  it('downgrades control-flow-only reachability to HIGH (potential) when no explicit IML data flow exists', () => {
    const blueprint = {
      name: 'Control-Flow Only Chain',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: { url: 'https://gateway.ai.cloudflare.com/v1/acc/gw/openai', data: 'static prompt' },
        },
        {
          id: 3,
          module: 'slack:CreateMessage',
          mapper: { text: 'Job finished' },
        },
      ],
    };

    const report = analyzeWorkflow(parseMakeBlueprint(blueprint));
    const trifecta = report.findings.find((f) => f.ruleId === 'LETHAL_TRIFECTA');

    expect(trifecta).toBeDefined();
    expect(trifecta?.severity).toBe('HIGH');
    expect(trifecta?.confidence).toBe('potential');
    expect(trifecta?.mitigatedByGateway).toBe(true);
  });

  it('returns CLEAN for a hardened gateway-routed workflow with no outbound egress', () => {
    const blueprint = {
      name: 'Hardened Internal Summarizer',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: {
            url: 'https://gateway.ai.cloudflare.com/v1/acc/gw/openai',
            data: '{{1.body}}',
          },
        },
        {
          id: 3,
          module: 'json:ParseJSON',
          mapper: { json: '{{2.data}}' },
        },
      ],
    };

    const report = analyzeWorkflow(parseMakeBlueprint(blueprint));

    expect(report.summary.verdict).toBe('CLEAN');
    expect(report.findings).toHaveLength(0);
    expect(report.summary.gatewayRoutedCount).toBe(1);
    expect(report.summary.gatewayBypassCount).toBe(0);
  });

  it('detects SSRF / Dynamic Exfiltration URLs tainted by untrusted input', () => {
    const blueprint = {
      name: 'Dynamic Webhook Callback',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: {
            url: 'https://hooks.example.com/notify?target={{1.callback}}',
            data: 'ok',
          },
        },
      ],
    };

    const report = analyzeWorkflow(parseMakeBlueprint(blueprint));
    const ssrf = report.findings.find((f) => f.ruleId === 'TAINTED_DYNAMIC_URL');

    expect(ssrf).toBeDefined();
    expect(ssrf?.severity).toBe('HIGH');
    expect(ssrf?.pathNodeIds).toEqual(['1', '2']);
  });
});

describe('taintEngine — adversarial graph DoS hardening', () => {
  it('terminates quickly without infinite loops on cyclic IR graphs', () => {
    const cyclicIR: WorkflowIR = {
      platform: 'make',
      name: 'Cyclic Attack Graph',
      nodes: {
        '1': {
          id: '1',
          platform: 'make',
          rawType: 'gateway:CustomWebHook',
          label: 'Source (#1)',
          roles: ['untrusted_source'],
          ai: { isLLM: false, gatewayStatus: 'none' },
          referencedNodeIds: ['3'],
          branchDepth: 0,
          hasFilter: false,
        },
        '2': {
          id: '2',
          platform: 'make',
          rawType: 'openai-gpt-3:CreateCompletion',
          label: 'LLM (#2)',
          roles: ['llm_processor'],
          ai: { isLLM: true, provider: 'openai', gatewayStatus: 'native_bypass' },
          referencedNodeIds: ['1'],
          branchDepth: 0,
          hasFilter: false,
        },
        '3': {
          id: '3',
          platform: 'make',
          rawType: 'google-email:ActionSendEmail',
          label: 'Sink (#3)',
          roles: ['outbound_sink'],
          ai: { isLLM: false, gatewayStatus: 'none' },
          referencedNodeIds: ['2'],
          branchDepth: 0,
          hasFilter: false,
        },
      },
      edges: [
        { from: '1', to: '2', kind: 'data_flow' },
        { from: '2', to: '3', kind: 'data_flow' },
        { from: '3', to: '1', kind: 'data_flow' }, // Cycle back to source
      ],
      entryNodeIds: ['1'],
      parseWarnings: [],
    };

    const start = performance.now();
    const report = analyzeWorkflow(cyclicIR);
    const elapsedMs = performance.now() - start;

    expect(elapsedMs).toBeLessThan(50);
    expect(report.summary.verdict).toBe('CRITICAL');
  });

  it('caps findings cleanly on dense bipartite graphs to prevent browser memory exhaustion', () => {
    const nodes: WorkflowIR['nodes'] = {};
    const edges: WorkflowIR['edges'] = [];

    nodes['llm'] = {
      id: 'llm',
      platform: 'make',
      rawType: 'http:ActionSendData',
      label: 'Gateway LLM (#llm)',
      roles: ['llm_processor'],
      ai: { isLLM: true, provider: 'gateway', gatewayStatus: 'gateway_routed' },
      referencedNodeIds: [],
      branchDepth: 0,
      hasFilter: false,
    };

    // 20 sources x 1 LLM x 15 sinks = 300 possible trifectas (> MAX_FINDINGS)
    for (let s = 0; s < 20; s++) {
      const id = `s${s}`;
      nodes[id] = {
        id,
        platform: 'make',
        rawType: 'gateway:CustomWebHook',
        label: `Source ${s}`,
        roles: ['untrusted_source'],
        ai: { isLLM: false, gatewayStatus: 'none' },
        referencedNodeIds: [],
        branchDepth: 0,
        hasFilter: false,
      };
      edges.push({ from: id, to: 'llm', kind: 'data_flow' });
    }

    for (let k = 0; k < 15; k++) {
      const id = `k${k}`;
      nodes[id] = {
        id,
        platform: 'make',
        rawType: 'slack:CreateMessage',
        label: `Sink ${k}`,
        roles: ['outbound_sink'],
        ai: { isLLM: false, gatewayStatus: 'none' },
        referencedNodeIds: ['llm'],
        branchDepth: 0,
        hasFilter: false,
      };
      edges.push({ from: 'llm', to: id, kind: 'data_flow' });
    }

    const report = analyzeWorkflow({
      platform: 'make',
      name: 'Combinatorial Bomb',
      nodes,
      edges,
      entryNodeIds: ['s0'],
      parseWarnings: [],
    });

    expect(report.findings).toHaveLength(ENGINE_LIMITS.MAX_FINDINGS);
    expect(report.summary.truncatedFindings).toBe(true);
  });
});