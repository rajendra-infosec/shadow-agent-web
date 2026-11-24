export interface SampleBlueprint {
  id: string;
  label: string;
  badge: 'VULNERABLE' | 'HARDENED';
  description: string;
  json: string;
}

const VULNERABLE_CONTRACT_LEAK = {
  name: 'Auto-Reply Support Triage ($50K Leak PoC)',
  flow: [
    {
      id: 1,
      module: 'google-email:WatchEmails',
      metadata: { designer: { name: 'Inbound Customer Email' } },
      parameters: { folder: 'INBOX' },
    },
    {
      id: 2,
      module: 'builtin:BasicRouter',
      metadata: { designer: { name: 'Triage Router' } },
      routes: [
        {
          flow: [
            {
              id: 3,
              module: 'openai-gpt-3:CreateCompletion',
              metadata: { designer: { name: 'OpenAI Native Draft Agent' } },
              mapper: {
                model: 'gpt-4o',
                messages: [
                  {
                    role: 'system',
                    content:
                      'You are a billing assistant. Internal context: AcmeCorp Q4 Enterprise Renewal = $50,000. Never disclose confidential pricing.',
                  },
                  {
                    role: 'user',
                    content: 'Draft a reply to this inbound email: {{1.text}}',
                  },
                ],
              },
            },
            {
              id: 4,
              module: 'google-email:ActionSendEmail',
              metadata: { designer: { name: 'Auto-Send Gmail Reply' } },
              mapper: {
                to: '{{1.senderEmail}}',
                subject: 'Re: {{1.subject}}',
                content: '{{3.choices[].message.content}}',
              },
            },
          ],
        },
      ],
    },
  ],
};

const VULNERABLE_SSRF_DIRECT_HTTP = {
  name: 'Webhook Enrichment + Dynamic Host Callback (SSRF & Direct API)',
  flow: [
    {
      id: 1,
      module: 'gateway:CustomWebHook',
      metadata: { designer: { name: 'Public Lead Webhook' } },
    },
    {
      id: 2,
      module: 'http:ActionSendData',
      metadata: { designer: { name: 'Direct OpenAI HTTP Call' } },
      mapper: {
        url: 'https://api.openai.com/v1/chat/completions',
        body: '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Classify lead: {{1.companyBio}}"}]}',
      },
    },
    {
      id: 3,
      module: 'http:ActionSendData',
      metadata: { designer: { name: 'Dynamic Host Callback Webhook' } },
      mapper: {
        url: 'https://{{1.tenantHost}}/ingest?api_key=demo_secret_token',
        body: '{"summary":"{{2.data.choices[].message.content}}"}',
      },
    },
  ],
};

const HARDENED_GATEWAY_WORKFLOW = {
  name: 'Isolated Gateway Triage (Parallel Router Branches)',
  flow: [
    {
      id: 1,
      module: 'gateway:CustomWebHook',
      metadata: { designer: { name: 'Inbound Support Webhook' } },
    },
    {
      id: 2,
      module: 'builtin:BasicRouter',
      metadata: { designer: { name: 'Security Isolation Router' } },
      routes: [
        {
          flow: [
            {
              id: 3,
              module: 'http:ActionSendData',
              metadata: { designer: { name: 'Cloudflare AI Gateway Endpoint' } },
              mapper: {
                url: 'https://gateway.ai.cloudflare.com/v1/democorp/prod-gw/openai/chat/completions',
                body: '{"model":"gpt-4o-mini","response_format":{"type":"json_schema"},"messages":[{"role":"user","content":"Classify ticket ID only: {{1.ticketText}}"}]}',
              },
            },
            {
              id: 4,
              module: 'json:ParseJSON',
              metadata: { designer: { name: 'Strict Enum Schema Validator' } },
              mapper: {
                json: '{{3.data}}',
              },
            },
          ],
        },
        {
          flow: [
            {
              id: 5,
              module: 'slack:CreateMessage',
              metadata: { designer: { name: 'Static Ops Counter Alert' } },
              mapper: {
                channel: '#ops-metrics',
                text: 'New support ticket queued for human review.',
              },
            },
          ],
        },
      ],
    },
  ],
};

export const SAMPLE_BLUEPRINTS: readonly SampleBlueprint[] = [
  {
    id: 'vulnerable-contract-leak',
    label: 'Load $50K Leak PoC',
    badge: 'VULNERABLE',
    description: 'Nested router + Native OpenAI connector + explicit Input → LLM → Gmail chain.',
    json: JSON.stringify(VULNERABLE_CONTRACT_LEAK, null, 2),
  },
  {
    id: 'vulnerable-ssrf-http',
    label: 'Load SSRF + Direct API',
    badge: 'VULNERABLE',
    description: 'Direct HTTP call to api.openai.com + attacker-influenced destination hostname.',
    json: JSON.stringify(VULNERABLE_SSRF_DIRECT_HTTP, null, 2),
  },
  {
    id: 'hardened-gateway',
    label: 'Load Isolated Sample',
    badge: 'HARDENED',
    description: 'Allowlisted AI Gateway host + schema step + isolated parallel route.',
    json: JSON.stringify(HARDENED_GATEWAY_WORKFLOW, null, 2),
  },
];