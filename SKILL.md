---
name: cybersecurity-audit
description: "Use when performing source code security audits on any project — deterministic pattern scanning, LLM contextual analysis, report generation in Markdown and JSON, with optional auto-fix after review."
version: 1.0.0
author: Cesar Schneider
license: MIT
metadata:
  hermes:
    tags: [cybersecurity, security, audit, vulnerability, code-review, auto-fix, sast]
    related_skills: [requesting-code-review, systematic-debugging]
---

# Cybersecurity Code Audit

## Overview

An AI-driven security auditor that performs **hybrid vulnerability detection** on source code projects. Combines **deterministic pattern scanning** (grep-based, fast, no API costs) with **deep LLM contextual analysis** (catches logic bugs, chained vulnerabilities). Also integrates **existing open-source SAST tools** like semgrep, bandit, or snyk when available. Produces structured **Markdown and JSON reports** with severity ratings, remediation guidance, and optional **auto-fix** after user review.

**Core principle:** Three-layer approach for best coverage. Layer 1 is deterministic (grep for known patterns). Layer 2 is tool-assisted (semgrep/bandit/snyk if installed). Layer 3 is LLM contextual analysis on data flows and business logic that simple patterns can't catch.

## When to Use

- User asks to "audit", "security scan", "cyber check", or "pentest" a codebase
- Before production deployment or after major refactors
- As a pre-commit or CI/CD security gate
- When reviewing third-party code or cloned repos

**Don't use for:** dependency-only vulnerability checks (use `pip audit`, `npm audit`, `snyk test` instead). This skill audits **source code logic**, not just package versions.

---

## The Three-Layer Architecture

### Layer 1: Deterministic Pattern Scanning (Fast)

Shell-based `grep` scans for known vulnerability patterns — instant, no API costs, zero false negatives on their domain.

| Scanner | What It Finds | Severity |
|---|---|---|
| SecretScanner | Hardcoded API keys, passwords, tokens, private keys | CRITICAL–HIGH |
| SQLInjectionScanner | f-strings, `.format()`, concat in SQL queries | CRITICAL |
| CommandInjectionScanner | `os.system()`, `subprocess shell=True`, `eval()` | CRITICAL |
| XSSScanner | `innerHTML`, `document.write`, `dangerouslySetInnerHTML` | HIGH |
| PathTraversalScanner | User input in file paths, `../` patterns | HIGH |
| InsecureConfigScanner | `DEBUG=True`, CORS allow-all, disabled TLS | MEDIUM–HIGH |
| WeakCryptoScanner | MD5/SHA1 passwords, DES, ECB mode, weak RSA | LOW–HIGH |

### Layer 2: SAST Tool-Assisted Scanning (When Available)

Detect and leverage installed open-source security scanners:

```bash
# semgrep — multi-language, free tier, OWASP Top 10 rules
which semgrep && semgrep scan --config auto /path/to/project --json 2>/dev/null

# bandit — Python-specific static analysis
which bandit && bandit -r /path/to/project -f json 2>/dev/null

# snyk — proprietary but comprehensive (requires auth, has free tier)
which snyk && snyk code test --json /path/to/project 2>/dev/null

# npm audit — Node.js dependency vulnerabilities
cd /path/to/project && npm audit --json 2>/dev/null

# pip-audit — Python dependency vulnerabilities
which pip-audit && pip-audit --format json 2>/dev/null
```

**If tools are installed** → merge their output into findings. **If not** → skip gracefully, Layers 1 + 3 still run.

### Layer 3: LLM Contextual Analysis (Deep Reasoning)

After deterministic scans, perform reasoning-based analysis on issues patterns miss:

1. **Input-to-sink flow analysis** — can user input (`request.args`, `req.body`) reach dangerous sinks (SQL, filesystem, subprocess) without validation?
2. **Authentication/authorization gaps** — routes without auth middleware, missing role checks, IDOR patterns
3. **Business logic vulnerabilities** — race conditions in payments, missing validation on critical fields, client-side trust assumptions
4. **Error information disclosure** — do error handlers leak stack traces, internal paths, or DB schemas?
5. **Chained vulnerabilities** — multiple weak points that combine into a full exploit path
6. **Architecture-level issues** — missing rate limiting, no CSRF protection, absent input sanitization globally

---

## Audit Workflow

### Step 1: Map the Codebase

Understand scope before scanning:

```bash
# Count source files by language
find /path/to/project -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" -o -name "*.rb" -o -name "*.go" \) -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/__pycache__/*" -not -path "*/venv/*" -not -path "*/dist/*" -not -path "*/build/*" | wc -l

# Identify frameworks and entry points
grep -rl "from flask\|import django\|from fastapi\|app = Flask()" /path/to/project --include="*.py" 2>/dev/null | head -5
grep -rl "express\|koa\|fastify\|app.get(\|router.get(" /path/to/project --include="*.js" --include="*.ts" 2>/dev/null | head -5

# Find data sinks (DB, filesystem, subprocess, HTTP client)
grep -rl "sqlite3\|mysql\.connect\|mongo\|redis\|psycopg" /path/to/project --include="*.py" --include="*.js" 2>/dev/null
```

### Step 2: Run Deterministic Pattern Scanners

Execute all applicable grep checks against source files:

```bash
# === 2a. Hardcoded Secrets ===
grep -rn "api_key\s*=\s*['\"].*['\"]" /path/to/project --include="*.py" --include="*.js" --include="*.ts" --include="*.yml" --include="*.env" 2>/dev/null | grep -v "os\.environ\|process\.env\|config\|/test\|/spec"
grep -rn "password\s*=\s*['\"][^'\"]\{6,\}['\"]" /path/to/project --include="*.py" --include="*.js" --include="*.yml" 2>/dev/null | grep -v "os\.environ\|process\.env\|/test\|/spec"
grep -rn "BEGIN.*PRIVATE KEY" /path/to/project --include="*.py" --include="*.js" --include="*.pem" --include="*.key" 2>/dev/null
grep -rn "AKIA[0-9A-Z]\{16\}" /path/to/project --include="*.py" --include="*.js" 2>/dev/null
grep -rn "mongodb://\|postgres://\|mysql://\|redis://" /path/to/project --include="*.py" --include="*.js" --include="*.yml" --include="*.env" 2>/dev/null | grep -v "os\.environ\|process\.env"

# === 2b. SQL Injection ===
grep -rn 'f"\s*SELECT\|f"\s*INSERT\|f"\s*UPDATE\|f"\s*DELETE\|f"\s*DROP' /path/to/project --include="*.py" 2>/dev/null
grep -rn "\.execute(.*f[" /path/to/project --include="*.py" 2>/dev/null
grep -rn '\.execute(.*\.format(' /path/to/project --include="*.py" 2>/dev/null
grep -rn "query.*\`.*SELECT\|query.*\`.*INSERT\|query.*\`.*UPDATE" /path/to/project --include="*.js" --include="*.ts" 2>/dev/null
grep -rn "['\"].*SELECT.*['\"].*\s*+\s*" /path/to/project --include="*.py" --include="*.js" 2>/dev/null | head -10

# === 2c. Command Injection ===
grep -rn "os\.system(" /path/to/project --include="*.py" 2>/dev/null
grep -rn "os\.popen(" /path/to/project --include="*.py" 2>/dev/null
grep -rn "subprocess\..*shell\s*=\s*True" /path/to/project --include="*.py" 2>/dev/null
grep -rn "\beval(" /path/to/project --include="*.py" --include="*.js" 2>/dev/null | grep -v "/test"
grep -rn "child_process.*exec(\|exec(" /path/to/project --include="*.js" --include="*.ts" 2>/dev/null

# === 2d. XSS ===
grep -rn "innerHTML\s*=\|document\.write(\|dangerouslySetInnerHTML\|v-html\s*=" /path/to/project --include="*.js" --include="*.jsx" --include="*.vue" --include="*.html" 2>/dev/null
grep -rn "render.*<.*>.*req\.\|render.*<.*>.*request\." /path/to/project --include="*.py" --include="*.js" 2>/dev/null

# === 2e. Path Traversal ===
grep -rn "open(.*req\.\|open(.*request\.\|send_file(.*req\.\|send_file(.*request\." /path/to/project --include="*.py" 2>/dev/null
grep -rn "fs\.readFile\|fs\.readFileSync\|createReadStream" /path/to/project --include="*.js" --include="*.ts" 2>/dev/null | grep -E "req\.|query\.|params\."

# === 2f. Insecure Configuration ===
grep -rn "DEBUG\s*=\s*True\|DEBUG\s*:\s*true" /path/to/project --include="*.py" --include="*.js" --include="*.yml" 2>/dev/null
grep -rn "Access-Control-Allow-Origin.*\*" /path/to/project --include="*.py" --include="*.js" 2>/dev/null
grep -rn "SESSION_COOKIE_SECURE\s*=\s*False\|SESSION_COOKIE_HTTPONLY\s*=\s*False" /path/to/project --include="*.py" 2>/dev/null

# === 2g. Weak Cryptography ===
grep -rn "hashlib\.md5(" /path/to/project --include="*.py" 2>/dev/null
grep -rn "hashlib\.sha1(" /path/to/project --include="*.py" 2>/dev/null
grep -rn "random\.randint\|random\.random\|random\.choice(" /path/to/project --include="*.py" 2>/dev/null | grep -v "test\|fixture"

# === 2h. Additional Patterns ===
grep -rn "pickle\.loads(\|pickle\.load(\|marshal\.loads(" /path/to/project --include="*.py" 2>/dev/null
grep -rn "yaml\.load(" /path/to/project --include="*.py" 2>/dev/null | grep -v "yaml\.safe_load\|yaml\.Loader"
grep -rn "requests\.get(.*req\.\|requests\.get(.*request\.\|urllib\.request.*req\." /path/to/project --include="*.py" 2>/dev/null
grep -rn "@csrf_exempt\|exempt_from_csrf\|CSRF.*=.*False" /path/to/project --include="*.py" 2>/dev/null
```

### Step 3: Run Available SAST Tools

```bash
# Detect and run semgrep (best free multi-language SAST)
if command -v semgrep &>/dev/null; then
  echo "=== Running semgrep ==="
  semgrep scan --config auto /path/to/project --json 2>/dev/null > /tmp/semgrep_results.json
fi

# Python-specific: bandit
if command -v bandit &>/dev/null; then
  echo "=== Running bandit ==="
  bandit -r /path/to/project -f json 2>/dev/null > /tmp/bandit_results.json
fi

# Dependency audit
cd /path/to/project
if [ -f package.json ]; then npm audit --json 2>/dev/null > /tmp/npm_audit.json; fi
if [ -f requirements.txt ] && command -v pip-audit &>/dev/null; then pip-audit --format json 2>/dev/null > /tmp/pip_audit.json; fi
```

**No tools installed?** Skip silently — Layers 1 and 3 still provide full coverage.

### Step 4: LLM Contextual Analysis

Read source files (especially entry points from Step 1) and analyze what grep can't detect:

1. **Trace user input flows**: Read route handlers — does request data reach SQL, filesystem, subprocess, or HTTP client without sanitization?
2. **Check auth enforcement**: Are route decorators or middleware enforcing authentication? Can unauthenticated users reach admin endpoints?
3. **Look for IDOR**: Are user IDs taken directly from request params without ownership checks?
4. **Inspect error handling**: Do try/except blocks expose `str(e)` or `e.stack` to the client?
5. **Evaluate rate limiting**: Any unbounded write/send operations (email, file upload, payments)?
6. **Review serialization**: `pickle.loads()`, `eval()` on external data, `__import__()` with user input?
7. **Review business logic**: Any state changes that need transactions but don't? Race conditions?
8. **Check secrets architecture**: Secrets from env vars or hardcoded? Are there fallback values in code?

### Step 5: Generate Reports

Save **two** report files — Markdown (human-readable) and JSON (machine-readable for auto-fix pipeline).

#### Markdown Report (`report-YYYY-MM-DD.md`)

```markdown
# Cybersecurity Audit Report

## Executive Summary
| Metric | Value |
|---|---|
| Project | {{project_name}} |
| Date | {{audit_date}} |
| Files Scanned | {{files_scanned}} |
| Total Vulnerabilities | {{total_findings}} |
| Critical | {{critical_count}} |
| High | {{high_count}} |
| Medium | {{medium_count}} |
| Low | {{low_count}} |

**Risk Score:** {{risk_score}}/100

## Critical Findings

### [CRIT-001] {{finding_title}}
- **Severity:** CRITICAL
- **Category:** {{category}} ({{cwe_id}})
- **File:** `{{filepath}}:{{line}}`
- **Description:** {{clear explanation}}
- **Proof of Concept:** {{how exploitation works}}
- **Code Snippet:**
  ```{{language}}
  // VULNERABLE (line {{line}}):
  {{vulnerable_code}}

  // FIXED:
  {{fixed_code}}
  ```

## High / Medium / Low Findings
...

## Remediation Priority
1. **Immediate (Critical):** ...
2. **Short-term (High):** ...
3. **Planned (Medium):** ...
4. **Backlog (Low):** ...
```

#### JSON Report (`findings-YYYY-MM-DD.json`)

```json
{
  "metadata": {
    "project": "",
    "path": "",
    "date": "YYYY-MM-DD",
    "scanner_version": "1.0.0",
    "layers_used": {
      "deterministic_patterns": true,
      "sast_tools_executed": false,
      "llm_contextual": true
    },
    "files_scanned": 0,
    "total_findings": 0,
    "risk_score": 0
  },
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "id": "CRIT-001",
      "severity": "critical",
      "category": "sql_injection",
      "cwe": "CWE-89",
      "file": "app.py",
      "line": 42,
      "vulnerable_code": "cursor.execute(f\"SELECT ... WHERE id = {user_id}\")",
      "description": "SQL query built with f-string — allows arbitrary SQL injection.",
      "remediation": "Use parameterized queries with placeholder values.",
      "fixed_code": "cursor.execute(\"SELECT ... WHERE id = %s\", (user_id,))",
      "autofix_ready": true
    }
  ]
}
```

Save to:
```
.audit/
├── report-YYYY-MM-DD.md
└── findings-YYYY-MM-DD.json
```

### Step 6: Auto-Remediation (After User Review Only)

**Only execute after user explicitly approves** ("fix", "auto-fix", "apply fixes") or the skill receives explicit confirmation.

1. Read JSON report findings where `autofix_ready: true`
2. For each finding:
   - Apply **targeted patch edits** (NOT full file rewrites)
   - Preserve existing function signatures and logic
   - Add comment: `# [SECURITY FIX] — {{cwe_id}} {{category}}`
3. **Safety rules:**
   - Max 5 files per auto-fix batch (beyond that, ask)
   - Never silently fix Critical findings
   - Create backup: `git stash push -m "pre-audit-backup"`
   - Log every change with before/after
4. **Post-fix verification:**
   - Re-run Layer 1 deterministic scans — confirm patterns gone
   - Run existing tests — no regressions
   - Generate patch: `git diff > .audit/fixes-YYYY-MM-DD.diff`
   - Commit: `git commit -m "[security-audit] Apply auto-fixes for {{N}} findings"`

---

## Severity Guidelines

| Severity | When to Apply | Examples |
|---|---|---|
| **CRITICAL** | Direct exploit, minimal effort | SQLi, command injection, exposed private keys |
| **HIGH** | Exploit possible with some effort | XSS, SSRF, IDOR, weak TLS |
| **MEDIUM** | Needs specific conditions or chaining | Debug mode on, CORS allow-all, missing CSRF |
| **LOW** | Defense-in-depth improvement | MD5 for non-security use, info disclosure |
| **INFO** | Best practice recommendation | No rate limiting, missing security headers |

## Common Pitfalls

1. **False positives on test files** — `/test`, `/tests`, `/spec`, `/fixtures` may have intentional vulnerable patterns. Mark as "demo/test code".
2. **Scanning build artifacts** — never scan `/dist`, `/build`, `/node_modules`, `/.venv`, `/.next`.
3. **Missing framework context** — `os.environ.get('SECRET_KEY')` is safe despite having `SECRET_KEY` in the line. Check surrounding code.
4. **Large codebases (100+ files)** — scan in priority order: entry points → data sinks → helpers. Don't process everything at once.
5. **Auto-fix overreach** — only fix the specific vuln. No refactoring, renaming, or style changes.
6. **Language differences** — Python uses `%s` or `?` for parameterized queries; Node.js uses `?` or `$1`. Check the DB driver before suggesting fixes.

## Verification Checklist

- [ ] Layer 1: Deterministic grep patterns run on all source files
- [ ] Layer 2: SAST tools attempted (semgrep/bandit/snyk/npm audit)
- [ ] Layer 3: LLM contextual analysis on entry points and data flows
- [ ] Findings de-duplicated (same issue not reported twice)
- [ ] Each finding has severity, CWE code, file:line, and remediation
- [ ] Markdown report at `.audit/report-YYYY-MM-DD.md`
- [ ] JSON report at `.audit/findings-YYYY-MM-DD.json`
- [ ] Summary presented to user before auto-fix
- [ ] Auto-fix changes verified with re-scan (no new issues introduced)
- [ ] Excluded: build artifacts, test fixtures, node_modules, venv
