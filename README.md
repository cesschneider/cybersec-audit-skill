# Cybersecurity Audit Skill

A Claude Agent skill that performs **hybrid source code security audits** — deterministic pattern scanning, SAST tool integration (semgrep/bandit/snyk/trivy), LLM contextual analysis, and architecture-level finding detection. Produces Markdown and JSON reports with optional auto-fix capability.

Includes intentionally vulnerable demo apps (Flask, Node.js, Go, React) to demonstrate the audit capability live.

---

## Setup

Choose your environment below. Step 2 (SAST tools) and Step 3 (output directory) are the
same for both.

---

### Option A — Claude Code (Anthropic CLI)

Claude Code uses `CLAUDE.md` for persistent instructions and `.claude/skills/` for reusable
slash-command workflows.

**Step A1 — Install as a global skill (available in any project)**

```bash
# Create the global skills directory
mkdir -p ~/.claude/skills/cybersecurity-audit

# Copy the skill file
cp SKILL.md ~/.claude/skills/cybersecurity-audit/SKILL.md
```

Invoke it in any Claude Code session with:
```
/cybersecurity-audit
```

**Step A2 — Or install as a project-level skill (scoped to this repo)**

```bash
# Run from inside the cloned repo
mkdir -p .claude/skills/cybersecurity-audit
cp SKILL.md .claude/skills/cybersecurity-audit/SKILL.md
```

Invoke it the same way:
```
/cybersecurity-audit
```

**Step A3 — Or inject via CLAUDE.md (no slash command needed)**

If you prefer the skill to load automatically for every session in this repo, append it to
your project's `CLAUDE.md`:

```bash
cat SKILL.md >> CLAUDE.md
```

Or create a user-level CLAUDE.md so the skill is always available globally:
```bash
cat SKILL.md >> ~/.claude/CLAUDE.md
```

**Verify it's loaded:**
```bash
# Inside the repo, start a Claude Code session and run:
/claude
# Then type /cybersecurity-audit — it should appear in autocomplete
```

---

### Option B — Hermes CLI

Hermes uses a `~/.hermes/skills/` directory with category subdirectories.

**Step B1 — Copy the skill into Hermes**

```bash
# Create the skill directory
mkdir -p ~/.hermes/skills/security/cybersecurity-audit

# Copy the skill file
cp SKILL.md ~/.hermes/skills/security/cybersecurity-audit/SKILL.md

# Copy reference files (optional but recommended)
mkdir -p ~/.hermes/skills/security/cybersecurity-audit/references
cp INSTALL.md ~/.hermes/skills/security/cybersecurity-audit/references/tool-install-guide.md
cp templates/findings-schema.json ~/.hermes/skills/security/cybersecurity-audit/references/
```

**Step B2 — Verify the skill is visible**

In your Hermes session:
```
/skills
```
You should see `cybersecurity-audit` listed. Hermes auto-loads the skill when you use
trigger phrases like "audit this app", "run a security scan", or "find vulnerabilities".

---

### Step 2 — Install SAST tools (both environments)

See [INSTALL.md](INSTALL.md) for full platform-specific instructions (Linux, macOS, cloud VMs).

Quick install:
```bash
pip install bandit semgrep njsscan pip-audit
npm install -g eslint eslint-plugin-security
```

If `bandit` or `semgrep` are not found after install, add the pip bin directory to PATH:
```bash
export PATH=$PATH:~/.local/bin
# Make it permanent:
echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc && source ~/.bashrc
```

### Step 3 — Create the output directory (both environments)

```bash
cd cybersec-audit-skill
mkdir -p .audit
# .audit/ is already in .gitignore in this repo
```

---

## Quick Start

```bash
# In your Claude Code or Hermes session:
"Audit the vulnerable-demo/flask-app directory"

# The agent will:
# 1. Map the codebase (languages, frameworks, entry points)
# 2. Run deterministic grep-based pattern scanners (Layer 1)
# 3. Run semgrep/bandit/snyk/trivy if available (Layer 2)
# 4. Detect architecture-level / multi-file gaps (Step 3b)
# 5. Perform LLM contextual analysis on data flows (Layer 3)
# 6. Calculate risk score (0–100) with severity breakdown
# 7. Generate structured report (Markdown + JSON)
# 8. Offer to auto-fix findings (after your approval)
```

---

## Structure

```
├── SKILL.md                                  # Agent skill — load this
├── INSTALL.md                                # SAST tool installation guide
├── README.md                                 # This file
├── docs/
│   └── risk-scoring.md                       # Risk scoring methodology
├── ci/
│   ├── layer0_dependency_audit.py            # Dependency audit CI script
│   ├── entropy_scan.py                       # Entropy-based secrets scanner
│   └── check_findings.py                     # CI gate — blocks on CRITICAL/HIGH
├── templates/
│   ├── report-template.md                    # Markdown report template
│   └── findings-schema.json                  # JSON findings schema
├── vulnerable-demo/
│   ├── flask-app/
│   │   ├── app.py                            # Flask — SQLi, cmd inj, XSS, path traversal
│   │   ├── config.py                         # Hardcoded secrets, DEBUG=True
│   │   ├── utils.py                          # Weak crypto, pickle deserialization
│   │   ├── requirements.txt
│   │   └── tests/
│   │       └── security_regression.py        # 20-test regression harness
│   ├── node-app/
│   │   ├── server.js                         # Express — SQLi, eval, SSRF, IDOR
│   │   └── package.json
│   ├── go-app/
│   │   ├── main.go                           # Go — SQLi, cmd inj, SSRF, weak crypto
│   │   └── go.mod
│   └── react-app/
│       └── src/
│           └── App.js                        # React — XSS, localStorage secrets, exposed keys
└── .github/
    └── workflows/
        └── security-audit.yml                # CI/CD security gate workflow
```

---

## Vulnerabilities in Demo Apps

### Flask App (`vulnerable-demo/flask-app/`)

| Vulnerability | Severity | CWE | Location |
|---|---|---|---|
| SQL Injection (f-string) | CRITICAL | CWE-89 | app.py:42 |
| SQL Injection (concat) | CRITICAL | CWE-89 | app.py:54 |
| Command Injection (os.system) | CRITICAL | CWE-78 | app.py:62 |
| Command Injection (subprocess) | CRITICAL | CWE-78 | app.py:68 |
| Reflected XSS | HIGH | CWE-79 | app.py:74 |
| Path Traversal | HIGH | CWE-22 | app.py:81 |
| SQL Injection in login | CRITICAL | CWE-89 | app.py:91 |
| No auth on admin endpoint | HIGH | CWE-284 | app.py:102 |
| Hardcoded SECRET_KEY | CRITICAL | CWE-798 | config.py |
| DEBUG = True | MEDIUM | CWE-200 | config.py |
| MD5 password hashing | HIGH | CWE-327 | utils.py |
| Weak random token | MEDIUM | CWE-330 | utils.py |
| Pickle deserialization | CRITICAL | CWE-502 | utils.py |

### Node.js App (`vulnerable-demo/node-app/`)

| Vulnerability | Severity | CWE | Location |
|---|---|---|---|
| SQL Injection (template) | CRITICAL | CWE-89 | server.js |
| Command Injection (exec) | CRITICAL | CWE-78 | server.js |
| eval() with user input | CRITICAL | CWE-95 | server.js |
| Path Traversal | HIGH | CWE-22 | server.js |
| Reflected XSS | HIGH | CWE-79 | server.js |
| SSRF | HIGH | CWE-918 | server.js |
| No auth on admin delete | HIGH | CWE-284 | server.js |
| IDOR on profile endpoint | MEDIUM | CWE-639 | server.js |

### Go App (`vulnerable-demo/go-app/`)

| Vulnerability | Severity | CWE | Location |
|---|---|---|---|
| SQL Injection | CRITICAL | CWE-89 | main.go |
| Command Injection | CRITICAL | CWE-78 | main.go |
| Path Traversal | HIGH | CWE-22 | main.go |
| SSRF | HIGH | CWE-918 | main.go |
| Hardcoded secrets | CRITICAL | CWE-798 | main.go |
| Weak crypto (MD5) | HIGH | CWE-327 | main.go |

### React App (`vulnerable-demo/react-app/`)

| Vulnerability | Severity | CWE | Location |
|---|---|---|---|
| XSS via dangerouslySetInnerHTML | HIGH | CWE-79 | App.js |
| Secrets in localStorage | HIGH | CWE-312 | App.js |
| Exposed API keys in JS | CRITICAL | CWE-798 | App.js |

---

## CI / CD Integration

The `.github/workflows/security-audit.yml` workflow runs on every PR and provides:

- **Layer 0 dependency audit** (`ci/layer0_dependency_audit.py`) — pip-audit, npm audit, trivy, license scanning
- **Entropy-based secrets detection** (`ci/entropy_scan.py`) — Shannon entropy scanning + git history scan
- **CI gate** (`ci/check_findings.py`) — blocks merge on CRITICAL or HIGH findings

Run locally:
```bash
python ci/layer0_dependency_audit.py /path/to/project
python ci/entropy_scan.py /path/to/project
python ci/check_findings.py .audit/findings-latest.json
```

---

## Risk Scoring

Risk scores use a weighted formula capped at 100:

```
score = min((CRITICAL × 25) + (HIGH × 10) + (MEDIUM × 3) + (LOW × 1), 100)
```

| Range | Label |
|---|---|
| 0 | Clean |
| 1–15 | Low Risk |
| 16–40 | Moderate Risk |
| 41–70 | High Risk |
| 71–99 | Critical Risk |
| 100 | Maximum Risk |

See [docs/risk-scoring.md](docs/risk-scoring.md) for full methodology including architecture-level findings and delta scoring.

---

## Documentation

| Document | Description |
|---|---|
| [README.md](README.md) | Project overview and setup |
| [INSTALL.md](INSTALL.md) | SAST tool installation (Linux, macOS, cloud VMs) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [docs/architecture.md](docs/architecture.md) | 3-layer audit pipeline internals |
| [docs/vulnerability-index.md](docs/vulnerability-index.md) | Full index of demo app vulnerabilities |
| [docs/risk-scoring.md](docs/risk-scoring.md) | Risk score formula and delta reporting |

---

## License

MIT — see [LICENSE](LICENSE) for full text.

