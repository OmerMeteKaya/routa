# Security Policy

## Supported Versions

routa is currently in active development. Security fixes are applied to the
`main` branch only.

| Branch | Supported |
|--------|-----------|
| main   |  Yes      |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Private Vulnerability Reporting](https://github.com/features/security/advisories)
to submit a report. Navigate to the repository's **Security** tab and click
**Report a vulnerability**.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept or minimal test case)
- Affected component (e.g., HTTP/2 parser, TLS layer, WebSocket)
- Any suggested mitigations

## Response Timeline

| Phase               | Target     |
|---------------------|------------|
| Acknowledgment      | 48 hours   |
| Initial assessment  | 5 days     |
| Fix + CVE request   | 30 days    |
| Public disclosure   | After fix  |

## Scope

**In scope:**

- Memory safety bugs (buffer overflows, use-after-free, etc.)
- Protocol parsing vulnerabilities (HTTP/1.1, HTTP/2, WebSocket)
- TLS/cryptography misconfigurations
- Authentication bypass (JWT, Basic Auth middleware)
- Denial-of-service via resource exhaustion
- Race conditions in multi-worker event loop
- Path traversal in static file serving

**Out of scope:**

- Vulnerabilities in dependencies (OpenSSL, zlib) — report those upstream
- Issues in example code (`examples/`)
- Theoretical weaknesses without a practical exploit path
- Performance issues that do not lead to a security impact

## CVE Tracking

CVEs will be requested through [MITRE](https://cveform.mitre.org/) or the
GitHub Advisory Database once a fix is confirmed.

## Security Hardening Notes

- All comments in source are in English; no credentials or tokens are stored
- CI runs `gitleaks` on every push to prevent secret leakage
- Dependencies are scanned nightly with `trivy` for known CVEs
- Static analysis runs `cppcheck` and `clang-tidy` on every push
- Fuzzing targets (libFuzzer): HTTP/1.1 parser, HPACK decoder, WebSocket framing, HTTP/2 frame parser
- ASAN + UBSAN on every CI push; MSAN + TSAN in nightly pipeline
- Graceful shutdown prevents mid-request data corruption on SIGTERM
