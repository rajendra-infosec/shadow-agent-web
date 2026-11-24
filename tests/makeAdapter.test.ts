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
});