import { describe, expect, it } from 'vitest';
import { PARSER_LIMITS, parseMakeBlueprint } from '../src/adapters/makeAdapter';

describe('makeAdapter — functional parsing', () => {
  it('parses deeply nested BasicRouter branches and extracts IML data-flow edges', () => {
    const blueprint = {
      name: 'Support Triage Leak PoC',
      flow: [
        {
          id: 1,
          module: 'gateway:CustomWebHook',
          metadata: { designer: { name: 'Customer Ticket Webhook' } },
        },
        {
          id: 2,
          module: 'builtin:BasicRouter',
          routes: [
            {
              flow: [
                {
                  id: 3,
                  module: 'openai-gpt-3:CreateCompletion',
                  mapper: {
                    messages: [
                      { role: 'user', content: 'Analyze ticket: {{1.body}}' },
                    ],
                  },
                },
                {
                  id: 4,
                  module: 'builtin:BasicRouter',
                  routes: [
                    {
                      flow: [
                        {
                          id: 5,
                          module: 'google-email:ActionSendEmail',
                          mapper: {
                            to: '{{1.senderEmail}}',
                            content: '{{3.choices[].message.content}}',
                          },
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    };

    const ir = parseMakeBlueprint(blueprint);

    expect(ir.name).toBe('Support Triage Leak PoC');
    expect(Object.keys(ir.nodes)).toHaveLength(5);
    expect(ir.nodes['1'].roles).toContain('untrusted_source');
    expect(ir.nodes['3'].ai.gatewayStatus).toBe('native_bypass');
    expect(ir.nodes['5'].roles).toContain('outbound_sink');
    expect(ir.nodes['5'].branchDepth).toBe(2);

    expect(ir.edges).toContainEqual({ from: '1', to: '3', kind: 'data_flow' });
    expect(ir.edges).toContainEqual({ from: '1', to: '5', kind: 'data_flow' });
    expect(ir.edges).toContainEqual({ from: '3', to: '5', kind: 'data_flow' });
  });

  it('walks Make.com onerror fallback branches so hidden sinks cannot evade detection', () => {
    const blueprint = {
      name: 'Error Handler Exfil',
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
              mapper: { text: 'Error on payload: {{1.body}}' },
            },
          ],
        },
      ],
    };

    const ir = parseMakeBlueprint(blueprint);

    expect(ir.nodes['3']).toBeDefined();
    expect(ir.nodes['3'].roles).toContain('outbound_sink');
    expect(ir.edges).toContainEqual({ from: '2', to: '3', kind: 'control_flow' });
    expect(ir.edges).toContainEqual({ from: '1', to: '3', kind: 'data_flow' });
  });

  it('distinguishes direct LLM HTTP bypass vs corporate AI Gateway routing', () => {
    const blueprint = {
      name: 'Gateway Comparison',
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        {
          id: 2,
          module: 'http:ActionSendData',
          mapper: { url: 'https://api.openai.com/v1/chat/completions', data: '{{1.body}}' },
        },
        {
          id: 3,
          module: 'http:ActionSendData',
          mapper: { url: 'https://gateway.ai.cloudflare.com/v1/acc/gw/openai', data: '{{1.body}}' },
        },
        {
          id: 4,
          module: 'http:ActionSendData',
          mapper: { url: 'https://ai-gw.corp.internal/v1/chat', data: '{{1.body}}' },
        },
      ],
    };

    const ir = parseMakeBlueprint(blueprint, {
      allowedGatewayHosts: ['ai-gw.corp.internal'],
    });

    expect(ir.nodes['2'].ai.gatewayStatus).toBe('direct_http_bypass');
    expect(ir.nodes['2'].roles).toContain('llm_processor');
    expect(ir.nodes['2'].roles).not.toContain('outbound_sink');

    expect(ir.nodes['3'].ai.gatewayStatus).toBe('gateway_routed');
    expect(ir.nodes['4'].ai.gatewayStatus).toBe('gateway_routed');
  });
});

describe('makeAdapter — AppSec / bug bounty hardening', () => {
  it('blocks prototype pollution payloads inside raw JSON strings', () => {
    const maliciousJson = JSON.stringify({
      name: 'Polluter',
      flow: [{ id: 1, module: 'gateway:CustomWebHook' }],
    }).replace('"name":"Polluter"', '"__proto__":{"polluted":true},"name":"Polluter"');

    const ir = parseMakeBlueprint(maliciousJson);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(ir.nodes['1']).toBeDefined();
  });

  it('fails closed on router recursion depth bombs', () => {
    let current: Record<string, unknown> = { id: 999, module: 'google-email:ActionSendEmail' };
    for (let depth = PARSER_LIMITS.MAX_ROUTER_DEPTH + 2; depth >= 1; depth--) {
      current = {
        id: depth,
        module: 'builtin:BasicRouter',
        routes: [{ flow: [current] }],
      };
    }

    expect(() => parseMakeBlueprint({ flow: [current] })).toThrow(/nesting depth/i);
  });

  it('rejects javascript: URI schemes in HTTP modules without crashing', () => {
    const blueprint = {
      flow: [
        {
          id: 1,
          module: 'http:ActionSendData',
          mapper: { url: 'javascript:alert(document.domain)' },
        },
      ],
    };

    const ir = parseMakeBlueprint(blueprint);
    expect(ir.nodes['1'].egressUrl).toBeUndefined();
    expect(ir.parseWarnings.some((w) => w.includes('non-HTTP(S)'))).toBe(true);
  });

  it('handles pathological unclosed IML braces in linear time (ReDoS check)', () => {
    const evilString = '{{'.repeat(20_000) + '1.body';
    const blueprint = {
      flow: [
        { id: 1, module: 'gateway:CustomWebHook' },
        { id: 2, module: 'openai-gpt-3:CreateCompletion', mapper: { prompt: evilString } },
      ],
    };

    const start = performance.now();
    const ir = parseMakeBlueprint(blueprint);
    const elapsedMs = performance.now() - start;

    expect(ir.nodes['2']).toBeDefined();
    expect(elapsedMs).toBeLessThan(100);
  });
});
