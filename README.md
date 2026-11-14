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
# (untrusted repo or archive? the agent runs Phase 0.0 hostile-repo triage first)
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

## How to Use This Skill

Pick the scenario that matches what you have. The agent follows the same phases when you ask in plain
language, and every script also runs standalone, without the agent.

| You have… | Say to the agent | What runs | Output |
|---|---|---|---|
| **Your own codebase** | "Audit this repo" / "security review before deploy" | Phase 0 context questions → threat model → Layers 1–11 (SAST, SCA, secrets, IaC, containers, API, auth, DAST, supply chain, headers/TLS) → triage → autofix offer | `.audit/report-YYYY-MM-DD.md` + `.audit/findings-YYYY-MM-DD.json` |
| **Untrusted code** (take-home test, client project, ZIP/tarball, unknown GitHub repo) | "Is this repo/zip safe to open?" | **Phase 0.0 hostile-repo triage first**: static scan for malicious git hooks, git-config exec keys, IDE auto-run tasks, install scripts, loader URLs and IOCs. Nothing is executed or extracted. | Verdict (`HOSTILE` / `SUSPICIOUS` / clean) + JSON findings |
| **A machine that already ran untrusted code** | "I ran a repo from a recruiter, was I compromised?" | Incident path: what fired, read-only host triage, rotation order, eradication | Triage report + response checklist |
| **A CI pipeline** | — | Workflow jobs below | PR checks, SARIF in the Security tab |

### Step by step: untrusted repository or archive

```bash
# 1. Never extract into your home folder or run git first. Scan the archive as-is:
python3 -I ci/hostile_repo_scan.py ~/Downloads/assessment.zip -o .audit/hostile-repo.json
#    exit 0 → no hostile indicators
#    exit 1 → CRITICAL/HIGH: STOP. Do not run git, npm, make, or open it in an IDE
#    exit 2 → scan error

# 2. Optional deeper look on an extracted copy (inside a VM):
yara -r rules/yara/git_hook_dropper.yar ./extracted-repo
find ./extracted-repo -path '*/.git/*hooks/*' -type f ! -name '*.sample' -exec ls -l {} \;

# 3. Only if clean: use git with hooks disabled, then run the normal audit
git -c core.hooksPath=/dev/null -c core.fsmonitor=false -C ./extracted-repo log --oneline
```

Read the findings by their check ID (full table in [docs/vulnerability-index.md](docs/vulnerability-index.md)):

| ID | Meaning | Typical action |
|---|---|---|
| `HR-HOOK` / `HR-SAMPLE` | Active or trojanized git hook (shows which git command fires it and whether it is executable) | Hostile, don't run git |
| `HR-GITCFG` | `.git/config` runs commands (`core.fsmonitor`, `core.hooksPath`, filters, textconv…) | Remove the key or override with `-c` |
| `HR-IDE` / `HR-PKG` | Folder-open IDE task, devcontainer command, npm/pip install script | Open in Restricted Mode; `npm ci --ignore-scripts` |
| `HR-DLX` / `HR-C2URL` / `HR-IOC` | `curl \| bash`, known loader URL shapes, known C2/hashes | Block the indicators; treat as malware |
| `HR-RAWIP` / `HR-OBF` / `HR-ARCHIVE` | Raw-IP URLs, obfuscated JS, archive shipping `.git/` | Review manually |

Keep the IOC list current by adding entries to `references/iocs/*.json`. The scanner loads every file
there automatically. Use `--iocs` to point at others.

### Step by step: suspected compromise (macOS)

```bash
bash ir/macos-triage.sh /path/to/suspect-repo 2026-11-05   # read-only; writes ~/Desktop/triage-*.txt
C2=203.0.113.7 bash ir/macos-triage.sh /path/to/repo        # hunt for a different C2 address
```

Then follow [references/hostile-repo-playbook.md](references/hostile-repo-playbook.md) §4: contain,
preserve, rotate from a clean device (crypto seed phrases first), hunt, reinstall, report.

### Standalone scripts

| Script | Purpose | Exit codes |
|---|---|---|
| `ci/hostile_repo_scan.py <dir\|zip\|tar>` | Hostile-repo trap scanner (Phase 0.0) | 0 clean · 1 critical/high · 2 error |
| `ci/layer0_dependency_audit.py <dir>` | pip-audit / npm audit / trivy | 0 clean · 1 critical/high |
| `ci/entropy_scan.py <dir> [--git-history]` | High-entropy secret detection | 0 |
| `ci/check_findings.py [--expect-findings]` | CI gate over `.audit/*.json` (or detection-regression mode for demo code) | 0 pass · 1 fail |

---

## Structure

```
├── SKILL.md                                  # Agent skill — load this
├── INSTALL.md                                # SAST tool installation guide
├── README.md                                 # This file
├── docs/
│   └── risk-scoring.md                       # Risk scoring methodology
├── ci/
│   ├── hostile_repo_scan.py                  # Phase 0.0 — git-hook / IDE / lifecycle trap scanner
│   ├── tests/test_hostile_repo_scan.py       # 31 unit tests (runtime fixtures, nothing armed)
│   ├── layer0_dependency_audit.py            # Dependency audit CI script
│   ├── entropy_scan.py                       # Entropy-based secrets scanner
│   └── check_findings.py                     # CI gate — blocks on CRITICAL/HIGH
├── rules/
│   ├── yara/git_hook_dropper.yar             # YARA — hook droppers, loader URLs, known hashes
│   └── sigma/git_hook_spawns_downloader_*.yml # Sigma — git hook spawning curl/wget (macOS, Linux)
├── ir/
│   └── macos-triage.sh                       # Read-only macOS compromise triage
├── references/
│   ├── hostile-repo-playbook.md              # Hostile repo handling, IR, detections, ATT&CK
│   └── iocs/contagious-interview.json        # IOC list loaded by the scanner
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

## Hostile Repository Triage (Phase 0.0)

Untrusted code (recruiter take-home tests, client projects, ZIPs from chat) can run attacker code
the moment you `git checkout`, `git commit`, `npm install`, or open it in an IDE. In the reference case,
a DPRK *Contagious Interview* lure shipped `.git/hooks/post-checkout` and friends running
`curl … /task/mac?id=483 | bash`, while every tracked file was clean.

Scan **before** running anything. The scanner works directly on archives and never executes or extracts:

```bash
python3 -I ci/hostile_repo_scan.py ~/Downloads/assessment.zip -o .audit/hostile-repo.json
# exit 0 = clean · 1 = CRITICAL/HIGH (stop; do not run git) · 2 = error
yara -r rules/yara/git_hook_dropper.yar ./extracted-repo      # optional
```

If a hostile repo was already used on a Mac, run the read-only triage and follow the playbook:

```bash
bash ir/macos-triage.sh ~/Downloads/assessment 2026-11-05
```

See [references/hostile-repo-playbook.md](references/hostile-repo-playbook.md).

---

## CI / CD Integration

The `.github/workflows/security-audit.yml` workflow runs on every PR and provides:

| Job | What it verifies |
|---|---|
| **Hostile Repo Triage (Phase 0.0)** | Scanner unit tests; this repo and the demo apps contain no planted traps; YARA and Sigma rules are valid |
| **Dependency Audit (Layer 0)** | pip-audit / npm audit on the demo apps (informational) and a Layer 0 script smoke test |
| **SAST (Layers 1 & 2)** | semgrep, bandit and the entropy scan run on the demo apps. **Detection regression:** `check_findings.py --expect-findings` fails if the scanners stop finding the planted vulnerabilities. SARIF goes to the Security tab. |
| **Security Regression Tests (Layer 3)** | The Flask regression suite **must fail** on the intentionally vulnerable branches (each failure is a detected vulnerability) and **must pass** on `autofix-security-fixes` |

The `vulnerable-demo/` apps are intentionally insecure, so CI checks that they are *detected*, not that
they are clean. On real application code, use the default gate mode (`python ci/check_findings.py`),
which blocks on any CRITICAL or HIGH finding.

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
| [references/hostile-repo-playbook.md](references/hostile-repo-playbook.md) | Hostile repository handling, incident response, detections |

---

## License

MIT — see [LICENSE](LICENSE) for full text.

