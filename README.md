# Shadow Agent

**Client-side static taint analyzer for Make.com (`.json`) blueprints.**

Shadow Agent inspects Make.com workflow exports locally in browser memory to surface candidate input-to-LLM-to-egress mapping chains, dynamic destination hostnames (potential SSRF), and direct vendor LLM endpoints—without uploading blueprints to any backend.

- **Live App:** https://shadow-agent-web.pages.dev
- **License:** MIT
- **Architecture:** 100% static Vite + React + TypeScript bundle (~78 KB gzipped), zero backend, zero telemetry.

---

## Detection Rules & Evidence-Based Verdicts

Shadow Agent reports **static graph evidence**, not confirmed runtime exploitability or security certification.

| Rule ID | Severity | Evidence Basis | What It Surfaces |
| :--- | :--- | :--- | :--- |
| `CANDIDATE_TRIFECTA_CHAIN` | `HIGH` / `MEDIUM` | `explicit_mapping` / `control_flow_only` | Untrusted input source → LLM processor → outbound sink path. `HIGH` requires explicit IML mapping (`{{...}}`) on both legs; `MEDIUM` indicates control-flow reachability only. |
| `TAINTED_DYNAMIC_HOST` | `HIGH` | `explicit_mapping` | HTTP module interpolates an IML expression into the **scheme, authority, hostname, or port** with a data-flow path from an untrusted source or LLM. Fixed-host query parameters do not trigger this rule. |
| `NATIVE_LLM_CONNECTOR_OBSERVED` | `MEDIUM` | `static_config` | Native vendor LLM module (e.g., `openai-gpt-3:*`) configured directly rather than via an allowlisted corporate AI Gateway hostname. |
| `DIRECT_PROVIDER_ENDPOINT_DECLARED` | `MEDIUM` | `static_config` | HTTP module targeting a direct vendor LLM endpoint (e.g., `api.openai.com`) instead of an allowlisted AI Gateway hostname. |

### Verdict States
- **`REVIEW_REQUIRED`**: One or more candidate findings were observed and require manual trust-boundary review.
- **`INCOMPLETE_ANALYSIS`**: Parser or graph traversal hit a safety ceiling (50k-char string scan, 500 IML blocks, 40-level object depth, 2,000 modules, 5,000 BFS visits, or duplicate module IDs). Fails closed—never reports a clean verdict when truncated.
- **`NO_CANDIDATES_FOUND`**: Zero findings within supported static coverage. **This is not a security certification.**

---

## Privacy & Defense-in-Depth

- **Local Execution:** Blueprints are parsed in browser memory (`File` / `Blob` API, 5 MB pre-parse cap) with no upload endpoint or analytics.
- **Strict Edge CSP (`public/_headers`):**

~~~http
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none';
Cross-Origin-Opener-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
~~~

*Note: `connect-src 'none'` and `form-action 'none'` provide strong browser defense-in-depth against common network exfiltration interfaces (`fetch`, XHR, WebSockets, `sendBeacon`), though CSP alone is not a universal navigation sandbox. Verify zero outbound requests in DevTools Network tab.*

- **Automatic URL Redaction:** Credentials (`user:pass@`), query values (`?api_key=[REDACTED]`), `#fragments`, and path-embedded webhook tokens (Slack `/services/...`, Discord `/api/webhooks/...`, Telegram `/bot...`, and long opaque path segments) are stripped before storage, UI rendering, or JSON report export.

### Verify Live Edge Headers

~~~bash
curl -sSI https://shadow-agent-web.pages.dev/ | grep -iE 'content-security-policy|cross-origin-opener-policy|x-content-type-options|x-frame-options|referrer-policy'
curl -s https://shadow-agent-web.pages.dev/ | grep -i "<script"
~~~

---

## What This Tool Does NOT Model (Known Limitations)

Static blueprint analysis cannot observe runtime state. Shadow Agent does **not** currently model:
- **Private data sensitivity:** Whether an upstream source actually contains PII, credentials, or confidential records.
- **Runtime guardrails:** Upstream prompt-injection filters, DLP policies, or corporate AI Gateway enforcement (`GATEWAY HOST MATCHED` only confirms an exact HTTPS hostname match, not active policy enforcement).
- **Indirect / cross-scenario flows:** Make Data Stores, sub-scenarios, custom/private apps, or webhook-to-webhook loops across separate blueprints.
- **Conditional filter evaluation:** Make.com filter expressions are noted, not symbolically evaluated.

---

## Local Development & Testing

~~~bash
npm ci
npm test        # 15 Vitest unit, redaction canary & adversarial DoS tests
npm run build   # TypeScript check + Vite production bundle (dist/)
~~~

---

## Research & Roadmap

Independent open-source security research project. Evaluating n8n/Zapier blueprint adapters and CLI/CI integration—share sanitized use cases or false-positive reports in GitHub Discussions.
