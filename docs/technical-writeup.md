Static Taint Analysis for Low-Code AI Workflows: Parsing Make.com IML Graphs and Enforcing Zero-Upload Scanning in the Browser

Repository: github.com/rajendra-infosec/shadow-agent-web

Live Browser Analyzer: shadow-agent-web.pages.dev

License: MIT

1. Empirical Motivation: System Prompts Are Not Data Boundaries

Enterprise security teams increasingly route sanctioned LLM traffic through centralized AI Gateways to enforce DLP, logging, and model allowlists. However, low-code automation platforms (such as Make.com and n8n) allow builders to wire untrusted external triggers directly into native vendor LLM connectors (openai-gpt-3:*) or raw HTTP modules (api.openai.com), bypassing corporate gateway controls entirely.

To test whether prompt-level guardrails reliably protect sensitive context in these workflows, we constructed a controlled Make.com lab scenario (Webhook -> OpenAI -> Gmail) in which an untrusted webhook supplied user input to an LLM whose system prompt contained synthetic confidential fields (Secret API Key: DUMMY-KEY-123 and Contract Value: $50,000), forwarding the model's response to an outbound Gmail action:

Run 1 (Probabilistic Leak): Despite explicit system-prompt instructions never to disclose internal sensitive data, the model produced a polite text refusal ("I can't help with encoding or sharing internal sensitive data...") followed immediately by Python, Node.js, and Shell Base64 example snippets that embedded the literal synthetic values (Contract Value: $50,000) from its system prompt. Because the workflow lacked deterministic egress filtering, the Gmail module transmitted the leak automatically.

Run 2 (Probabilistic Block): Re-running the exact same payload yielded a clean refusal using a generic "Sample data" placeholder with zero disclosure.

This demonstrates two structural realities in low-code AI workflows:

Probabilistic Defenses Fail Against Deterministic Sinks: When an LLM sits directly upstream of an unguarded outbound action (email, Slack, webhook), a single non-compliant generation is sufficient to exfiltrate sensitive context.

Blueprint Blind Spots: Security teams often lack visibility into exported workflow definitions to see where untrusted inputs reach LLMs, whether direct vendor connectors bypass an AI Gateway, or whether dynamic URLs introduce SSRF risk.

Shadow Agent was built to answer a focused static-analysis question: What can an exported Make.com .json blueprint reliably prove about untrusted-input -> LLM -> outbound egress paths—and where must static analysis fail closed?

2. Privacy Threat Model: Zero-Upload Browser Execution

Make.com workflow blueprints frequently contain embedded webhook secrets, internal service hostnames, OAuth metadata, and proprietary business logic. Asking engineers to upload raw blueprints to a hosted SaaS scanner introduces an unacceptable data-exposure risk.

Shadow Agent executes 100% locally in browser memory (~78 KB gzipped client bundle) with no backend API, no analytics, and no telemetry:

Edge Content Security Policy: Served with Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none', alongside Cross-Origin-Opener-Policy: same-origin, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Referrer-Policy: no-referrer.

Containment Scope: connect-src 'none' blocks fetch, XMLHttpRequest, WebSocket, EventSource, and sendBeacon egress at the browser layer. Because CSP connect-src does not govern top-level document navigation, the full source is MIT-licensed and locally buildable for air-gapped verification.

Automatic Secret Redaction: Before findings touch React state or the downloadable JSON report, URLs are sanitized to strip userinfo@ credentials, query parameter values, #fragments, and path-embedded webhook tokens (Slack, Discord, Telegram, and Make hook URLs), verified via canary unit tests.

3. Intermediate Representation (IR) & Graph Lowering

Make.com blueprints are not flat lists; they contain nested BasicRouter route arrays and onerror exception-handling branches. makeAdapter.ts lowers raw blueprint JSON into a typed directed graph (WorkflowIR):

Node Role Classification: Each module is classified into functional roles—untrusted_source (e.g., gateway:CustomWebHook, google-email:WatchEmails), llm_processor (native LLM connectors or HTTP calls targeting known vendor LLM endpoints), outbound_sink (email, messaging, and external HTTP actions), or neutral—plus optional corporate AI Gateway allowlist matching.

Control-Flow Topology: Sequential links, router branches, and onerror fallback paths are preserved as control_flow edges so reachability analysis accounts for error-path execution as well as primary routes.

4. False-Positive Engineering in Static Taint Analysis

Naively grepping blueprint JSON for module names and {{...}} strings creates unacceptable false positives. Shadow Agent enforces three structural distinctions:

A. Separating Explicit Data-Flow from Control-Flow Filters

Make modules attach branching conditions under filter objects (e.g., checking {{2.status}} == "ok" before sending a static notification). makeAdapter.ts extracts data_flow edges exclusively from module mapper payloads and excludes filter conditions from data-flow taint propagation:

When untrusted input reaches an LLM and the LLM's output is explicitly mapped into an outbound sink ({{3.result}}), the engine emits a HIGH severity CANDIDATE_TRIFECTA_CHAIN (evidenceBasis: 'explicit_mapping').

When modules are connected only via routing order or filter conditions without explicit payload mapping, the chain is downgraded to LOW (evidenceBasis: 'control_flow_only').

B. Quote-Aware IML Reference Extraction

Make's Information Mapping Language (IML) supports nested function calls inside {{...}} blocks, such as {{trim(1.body)}} or {{replace(1.body; "literal 2.body"; "sanitised")}}. A naive regex scanning the entire {{...}} block would misinterpret "literal 2.body" inside a string argument as a dependency on module 2.

Shadow Agent passes each {{...}} expression through a lightweight quote-aware lexer (stripQuotedStrings) that tracks single quotes, double quotes, and backslash escapes—stripping literal string contents before extracting \b(\d+)\. module references.

C. Host-Only SSRF Detection

Dynamic URLs in HTTP modules frequently interpolate untrusted parameters into query strings on a trusted host (e.g., https://api.trusted.example.com/v1/items?id={{1.id}}). Flagging every interpolated URL creates alert fatigue.

Shadow Agent parses the URL authority, strips any userinfo@ prefix (https://{{1.user}}@fixed.example.com/callback), and inspects only the scheme, hostname, and port for {{...}} interpolation—emitting HIGH TAINTED_DYNAMIC_HOST only when untrusted input can alter the destination host itself.

5. Bounded Execution & Fail-Closed Semantics

Static analyzers exposed to untrusted or deeply nested workflow files must defend against parser and graph-traversal exhaustion. Shadow Agent enforces hard resource ceilings across both parsing and analysis:

Parser Ceilings: 5 MB maximum input size, 40-level nested router recursion cap, and 2,000-module limit.

Traversal Budgets: 5,000-visit cap per breadth-first search (MAX_BFS_VISITS), 50,000-visit global budget across analyzeWorkflow() (MAX_TOTAL_BFS_VISITS), and a 200-finding ceiling (MAX_FINDINGS).

Fail-Closed Verdict: If any parser ceiling or traversal budget is exhausted, the engine sets analysisStatus: 'PARTIAL' and returns the verdict INCOMPLETE_ANALYSIS. It never returns NO_CANDIDATES_FOUND on a truncated scan.

6. Deterministic Remediations & Static Analysis Boundaries

Static blueprint scanning identifies structural risk, but remediation must be enforced deterministically outside the LLM:

Pre-LLM Context Minimization: Strip unnecessary CRM or database fields at the retrieval layer before constructing the prompt.

Deterministic Egress Control: Place a deterministic Make Router/Filter between LLM output and external actions to enforce strict schema validation, regex/DLP checks, and destination allowlists.

Privilege Separation via Constrained Schemas: Decouple untrusted input parsing (zero sensitive context access, strict JSON intent output) from privileged downstream actions mapped by deterministic application logic.

Least-Privilege Service Accounts: Replace personal or administrative OAuth connections with dedicated service identities scoped strictly to required resources.

Scope Limitations: Static JSON blueprint analysis cannot inspect runtime variable stores (util:SetVariable / util:GetVariable), evaluate external OAuth token scopes, trace dynamic sub-scenarios, or inspect live prompt/response payloads. A NO_CANDIDATES_FOUND result reflects supported static coverage only and is not a security certification.