# Architecture

This document describes how the cybersecurity audit skill works internally.

## Overview

The skill uses a three-layer pipeline that combines speed, coverage, and depth:

```
Source Code
     │
     ▼
┌─────────────────────────────────┐
│  Layer 1: Deterministic Grep    │  Fast. No API cost. Zero false negatives
│  Pattern-based scanners         │  on their specific domain.
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Layer 2: SAST Tool Integration │  semgrep, bandit, njsscan, eslint,
│  External static analyzers      │  gosec, pip-audit, npm audit
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Layer 3: LLM Contextual        │  Data flow tracing, auth gap detection,
│  Deep reasoning analysis        │  business logic, chained vulns
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Triage + Architecture Review   │  De-duplication, ARCH-### findings,
│                                 │  severity upgrades for pervasive issues
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Report Generation              │  .audit/findings-YYYY-MM-DD.json
│                                 │  .audit/report-YYYY-MM-DD.md
└─────────────────────────────────┘
```

---

## Layer 1 — Deterministic Pattern Scanning

Shell-based grep scans for known vulnerability signatures. Runs first because it is
instant, requires no network access, and produces zero false negatives within its domain.

| Scanner | Patterns Detected | Severity |
|---|---|---|
| SecretScanner | Hardcoded API keys, passwords, tokens, private keys | CRITICAL–HIGH |
| SQLInjectionScanner | f-strings, `.format()`, concatenation in SQL queries | CRITICAL |
| CommandInjectionScanner | `os.system()`, `subprocess shell=True`, `eval()` | CRITICAL |
| XSSScanner | `innerHTML`, `document.write`, `dangerouslySetInnerHTML` | HIGH |
| PathTraversalScanner | User input in file paths, `../` traversal patterns | HIGH |
| InsecureConfigScanner | `DEBUG=True`, CORS wildcard, disabled TLS | MEDIUM–HIGH |
| WeakCryptoScanner | MD5/SHA1 for passwords, DES, ECB mode | LOW–HIGH |

---

## Layer 2 — SAST Tool Integration

The skill detects and invokes installed open-source SAST tools and merges their findings
into the unified report. If a tool is not installed it is skipped silently — Layers 1
and 3 still provide full coverage.

| Tool | Language(s) | What it adds |
|---|---|---|
| semgrep | Python, JS, TS, Go, Java, Ruby, 30+ | OWASP Top 10, secrets, custom rules |
| bandit | Python | subprocess, pickle, MD5, hardcoded creds |
| njsscan | Node.js | Express injection, eval, prototype pollution |
| eslint-plugin-security | JavaScript | XSS, regex DoS, unsafe deserialization |
| gosec | Go | SQLi, cmd injection, TLS, file permissions |
| pip-audit | Python deps | Known CVEs in installed packages |
| npm audit | Node.js deps | Known CVEs in npm dependencies |

Tool output is parsed and normalized into the findings schema before merging.
Duplicates are eliminated by `(file, line, cwe)` key.

---

## Layer 3 — LLM Contextual Analysis

After deterministic scans, the LLM reads entry points and data sinks to find issues
that pattern matching cannot:

1. **Input-to-sink flow tracing** — can `request.args` / `req.body` reach SQL, filesystem,
   subprocess, or HTTP client without sanitization?
2. **Auth and authorization gaps** — routes without middleware, missing role checks, IDOR
3. **Business logic vulnerabilities** — race conditions, missing validation, client-side trust
4. **Error information disclosure** — stack traces or DB schemas leaking to the client
5. **Chained vulnerabilities** — multiple weak points that form a full exploit path
6. **Architecture-level gaps** — missing rate limiting, no CSRF, absent global input sanitization

---

## Architecture-Level Findings (ARCH-###)

Some vulnerabilities are not isolated to a single file — they represent a systemic gap
across the entire codebase. These are classified as `ARCH-###` findings.

Rules:
- `"file": "MULTIPLE"` with an `"affected_files": [...]` array
- `"line": null`
- `"architecture_level": true`
- Scored one severity level higher than the equivalent single-file finding
- Counted **once** regardless of how many files are affected

Example: missing auth middleware globally = CRITICAL (vs HIGH for a single unguarded route).

---

## Risk Scoring

```
raw_score = (CRITICAL × 25) + (HIGH × 10) + (MEDIUM × 3) + (LOW × 1)
risk_score = min(raw_score, 100)
```

| Score | Label |
|---|---|
| 0 | Clean |
| 1–15 | Low Risk |
| 16–40 | Moderate Risk |
| 41–70 | High Risk |
| 71–99 | Critical Risk |
| 100 | Maximum Risk |

See `docs/risk-scoring.md` for delta scoring (pre-fix vs post-fix comparison).

---

## Report Outputs

Both files are written to `.audit/` (gitignored — generated locally, never committed):

**`findings-YYYY-MM-DD.json`** — machine-readable, follows `templates/findings-schema.json`:
- metadata: date, repo, tool versions, layers used, risk score
- summary: counts per severity
- findings: array of finding objects with id, severity, cwe, file, line, autofix_ready

**`report-YYYY-MM-DD.md`** — human-readable, follows `templates/report-template.md`:
- Executive summary table
- Finding detail per severity tier (code snippets, PoC, remediation)
- Remediation priority queue

---

## CI Pipeline

Three parallel jobs defined in `.github/workflows/security-audit.yml`:

```
PR / Push
    │
    ├── dependency-audit   pip-audit + npm audit on demo app deps
    │
    ├── sast               semgrep (OWASP Top 10) + bandit + entropy scan
    │                      SARIF uploaded to GitHub Security tab
    │
    └── security-tests     Flask regression tests + Node auth/IDOR tests
```

The `ci/check_findings.py` gate blocks merge if any CRITICAL or HIGH findings are present
in the scan output.
