# Security Policy

## Reporting a Vulnerability

If you discover a security issue in Shadow Agent—such as a parser DoS bypass, XSS vector, CSP regression, or secret-redaction leak—please report it responsibly via **GitHub Private Vulnerability Reporting** on this repository (`Security` → `Advisories` → `Report a vulnerability`).

Please include:
- A minimal, sanitized proof-of-concept blueprint or reproduction steps
- Expected vs. actual behavior
- Browser and version (if UI/CSP-related)

## Scope

In scope:
- Client-side code execution (XSS) or prototype pollution in `src/adapters/` or `src/engine/`
- Browser-freeze / ReDoS / unbounded recursion inputs bypassing parser or BFS ceilings
- Secret-redaction bypasses leaking URL credentials, query values, or webhook tokens into UI state or exported JSON reports
- CSP or security header misconfigurations on the hosted static deployment

Out of scope:
- False positives/negatives inherent to static analysis of unmodeled Make.com features (please open a standard GitHub Issue or Discussion instead)
