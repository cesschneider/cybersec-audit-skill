# Cybersecurity Audit Skill

A Claude Agent skill that performs hybrid source code security audits — deterministic pattern scanning, SAST tool integration (semgrep/bandit/snyk), and LLM contextual analysis. Produces Markdown and JSON reports with optional auto-fix capability.

Includes an intentionally vulnerable demo app to demonstrate the audit capability live.

## Setup

See [INSTALL.md](INSTALL.md) for full tool installation and configuration.

## Quick Start

```
# If loaded as a Claude Agent skill:
"Audit the vulnerable-demo/flask-app directory"

# The agent will:
# 1. Scan for deterministic vulnerability patterns
# 2. Run semgrep/bandit/snyk if available
# 3. Perform LLM contextual analysis
# 4. Generate a structured report (Markdown + JSON)
# 5. Offer to auto-fix any findings (after your approval)
```

## Structure

```
├── SKILL.md                              # The agent skill (load this)
├── vulnerable-demo/
│   ├── flask-app/
│   │   ├── app.py                        # Flask app with SQLi, cmd inj, XSS
│   │   ├── config.py                     # Hardcoded secrets, debug mode
│   │   ├── utils.py                      # Weak crypto, path traversal
│   │   └── requirements.txt
│   ├── node-app/
│   │   ├── server.js                     # Express app with SQLi, eval, SSRF
│   │   └── package.json
└── templates/
    ├── report-template.md                # Markdown report template
    └── findings-schema.json              # JSON findings schema
```

## Vulnerabilities in Demo

| App | Vulnerability | Severity | Location |
|-----|-------------|----------|----------|
| Flask | SQL Injection (f-string) | CRITICAL | app.py:42 |
| Flask | SQL Injection (concat) | CRITICAL | app.py:54 |
| Flask | Command Injection (os.system) | CRITICAL | app.py:62 |
| Flask | Command Injection (subprocess) | CRITICAL | app.py:68 |
| Flask | Reflected XSS | HIGH | app.py:74 |
| Flask | Path Traversal | HIGH | app.py:81 |
| Flask | SQL Injection in login | CRITICAL | app.py:91 |
| Flask | No auth on admin endpoint | HIGH | app.py:102 |
| Flask | Hardcoded SECRET_KEY | CRITICAL | config.py |
| Flask | DEBUG = True | MEDIUM | config.py |
| Flask | MD5 password hashing | HIGH | utils.py |
| Flask | Weak random token | MEDIUM | utils.py |
| Flask | pickle deserialization | CRITICAL | utils.py |
| Node | SQL Injection (template) | CRITICAL | server.js |
| Node | Command Injection (exec) | CRITICAL | server.js |
| Node | eval() with user input | CRITICAL | server.js |
| Node | Path Traversal | HIGH | server.js |
| Node | Reflected XSS | HIGH | server.js |
| Node | SSRF | HIGH | server.js |
| Node | No auth on admin delete | HIGH | server.js |
| Node | IDOR on profile endpoint | MEDIUM | server.js |

## License

MIT — Use freely in any project.
