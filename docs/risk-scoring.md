# Risk Scoring Methodology

## Overview

The Cybersecurity Audit Skill uses a **normalized 0–100 risk score** to summarize the overall security posture of a codebase. The score is computed from the severity distribution of all findings, weighted and capped to produce a human-readable signal.

---

## Severity Weights

| Severity | Weight | Rationale |
|----------|--------|-----------|
| CRITICAL | 25 | Direct exploitation with minimal attacker effort — SQL injection, RCE, exposed private keys |
| HIGH | 10 | Exploitable with some effort or conditions — XSS, SSRF, IDOR, weak TLS |
| MEDIUM | 3 | Requires specific conditions or chaining — DEBUG=True, CORS allow-all, missing CSRF |
| LOW | 1 | Defense-in-depth improvements — MD5 for non-auth use, verbose error messages |
| INFO | 0 | Best practice recommendations — no rate limiting, missing security headers |

---

## Formula

```
raw_score = (CRITICAL × 25) + (HIGH × 10) + (MEDIUM × 3) + (LOW × 1)
risk_score = min(raw_score, 100)
```

The score is **capped at 100** — it's a normalized risk signal, not an unbounded penalty accumulator.

---

## Score Bands

| Range | Label | Recommended Action |
|-------|-------|--------------------|
| 0 | **Clean** | No action needed — maintain posture |
| 1–15 | **Low Risk** | Schedule fixes in next sprint |
| 16–40 | **Moderate Risk** | Fix HIGH+ findings before next release |
| 41–70 | **High Risk** | Block deployment until CRITICAL/HIGH resolved |
| 71–99 | **Critical Risk** | Immediate remediation required |
| 100 | **Maximum Risk** | Do not deploy — full security review needed |

---

## Example Calculation

A typical vulnerable demo app might have:

- 3 CRITICAL findings (SQL injection, command injection, hardcoded secret)
- 4 HIGH findings (XSS, path traversal, SSRF, IDOR)
- 2 MEDIUM findings (DEBUG=True, CORS allow-all)
- 1 LOW finding (MD5 weak hash)

```
raw_score = (3 × 25) + (4 × 10) + (2 × 3) + (1 × 1)
          = 75 + 40 + 6 + 1
          = 122 → capped at 100
risk_score = 100  ← Maximum Risk
```

After autofix (e.g. 2 CRITICAL, 3 HIGH resolved):

```
raw_score = (1 × 25) + (1 × 10) + (2 × 3) + (1 × 1)
          = 25 + 10 + 6 + 1
          = 42
risk_score = 42  ← High Risk (still needs CRITICAL fix)
```

---

## Multi-File / Architecture-Level Findings

Some findings span multiple files or represent system-wide gaps rather than a single vulnerable line. These are scored differently:

### Architecture-Level Severity Upgrade

When a vulnerability class is **pervasive** (appears in 3+ files or affects the entire request pipeline), upgrade severity by one level:

| Original | Upgraded | Example |
|----------|----------|---------|
| HIGH | CRITICAL | Missing auth middleware applied globally |
| MEDIUM | HIGH | No input validation on any endpoint |
| LOW | MEDIUM | Debug logging enabled across all modules |

### Architecture-Level Finding IDs

Use `ARCH-###` prefix to distinguish from single-file findings:

```
ARCH-001 — No authentication middleware on any route (affects 12 endpoints)
ARCH-002 — All database queries use string concatenation (affects 5 files)
ARCH-003 — Secrets loaded from hardcoded fallbacks if env vars missing (affects 3 modules)
```

### Scoring Architecture Findings

Architecture findings count as **one finding at the upgraded severity**. Do not multiply per affected file — that would double-count.

---

## Delta Scoring (Pre/Post Fix)

After auto-remediation, generate a **risk delta** to quantify improvement:

```
delta = pre_fix_score - post_fix_score
improvement_pct = (delta / pre_fix_score) × 100
```

Report format:
```
Risk Score: 100 → 42  (▼ 58 points, 58% improvement)
Findings:   21 → 7    (▼ 14 fixed, 3 critical resolved)
```

---

## JSON Schema Fields

The `findings-YYYY-MM-DD.json` metadata block should include:

```json
{
  "metadata": {
    "risk_score": 100,
    "risk_label": "Maximum Risk",
    "score_breakdown": {
      "critical": 3,
      "high": 4,
      "medium": 2,
      "low": 1,
      "raw_score": 122,
      "capped": true
    }
  }
}
```

---

## References

- CVSS v3.1 Base Score methodology: https://www.first.org/cvss/v3.1/specification-document
- OWASP Risk Rating Methodology: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- CWE Severity Guidance: https://cwe.mitre.org/cwss/cwss_v1.0.1.html
