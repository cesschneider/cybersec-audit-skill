# SAST Tool Installation Guide for Linux

This guide covers installing and configuring the security scanning tools used by the Cybersecurity Audit Skill. All tools listed are free and open-source.

## System Requirements

- **OS**: Linux (Ubuntu/Debian/RHEL/Arch) or WSL2
- **Python**: 3.9+ (for semgrep, bandit, pip-audit)
- **Node.js**: 18+ (optional, for npm audit / JavaScript projects)
- **Git**: for tracking findings and auto-fix changes
- **Root/sudo**: for system-wide installs, or use pip `--user`

---

## Core Tools

### semgrep — Multi-language static analysis (OWASP Top 10)

The primary SAST scanner — supports Python, JavaScript, TypeScript, Go, Java, Ruby, and 30+ languages.

```bash
# Install via pip (recommended)
pip install semgrep

# Verify
semgrep --version
```

**What it detects:** SQL injection, command injection, XSS, hardcoded secrets, insecure crypto, deserialization, and OWASP Top 10 vulnerabilities across 30+ languages.

**Alternative standalone binary:**
```bash
curl -fL https://semgrep.dev/install.sh | bash
```

### bandit — Python security linter

Specialized static analysis for Python codebases.

```bash
pip install bandit

# Verify
bandit --version
```

**What it detects:** Hardcoded SQL expressions, subprocess shell usage, weak crypto (MD5/SHA1), pickle deserialization, hardcoded bind-all-interfaces, TLS/SSL issues, hardcoded passwords.

**Usage:**
```bash
# Full scan with high-severity and above
bandit -r /path/to/project -f json -ll > bandit_results.json

# Human-readable output
bandit -r /path/to/project -ll
```

### pip-audit — Python dependency vulnerabilities

Scans installed Python packages against known CVE databases.

```bash
pip install pip-audit

# Verify
pip-audit --version
```

**What it detects:** Known vulnerabilities (CVEs) in Python packages from PyPI advisories.

**Usage:**
```bash
pip-audit --format json > pip_audit_results.json
```

---

## Extended Tools

### snyk — Comprehensive commercial scanner (free tier)

The most comprehensive scanner — covers code, dependencies, containers, IaC, and licenses.

```bash
# Linux via npm
npm install -g snyk

# Or standalone binary
curl -sSfL https://static.snyk.io/cli/latest/snyk-linux -o snyk
chmod +x snyk && sudo mv snyk /usr/local/bin/

# Authenticate (get free token at https://snyk.io)
snyk auth

# Verify
snyk --version
```

**What it detects:** Code vulnerabilities, dependency CVEs, container image issues, IaC misconfigurations (Docker, Terraform, K8s), license compliance.

### trivy — All-in-one vulnerability scanner

Security scanner for containers, filesystems, infrastructure-as-code, and SBOM generation.

#### Option A: Debian/Ubuntu via apt
```bash
sudo apt-get install wget apt-transport-https gnupg -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy -y
```

#### Option B: Standalone binary
```bash
wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(uname -s)_$(uname -m).tar.gz -O /tmp/trivy.tar.gz
tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
rm /tmp/trivy.tar.gz
```

**Verify:**
```bash
trivy --version
```

**What it detects:** Container image vulnerabilities, filesystem scans, IaC misconfigurations, SBOM generation, license scanning.

---

## Quick Start: One-Liner Installation

Install all core tools at once:

```bash
pip install --upgrade semgrep bandit pip-audit
```

Full setup including extended tools:

```bash
# Core SAST tools
pip install --upgrade semgrep bandit pip-audit

# Node.js tools (if npm is available)
which npm && npm install -g snyk 2>/dev/null || true

# Trivy binary scanner
wget -q https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(uname -s)_$(uname -m).tar.gz -O /tmp/trivy.tar.gz
tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
rm /tmp/trivy.tar.gz

echo "All tools installed!"
```

---

## Verify Installation

Run this to check what's available:

```bash
echo "=== SAST Tools ==="
echo -n "semgrep:   " && (which semgrep && semgrep --version 2>/dev/null || echo "NOT INSTALLED")
echo -n "bandit:    " && (which bandit && bandit --version 2>/dev/null || echo "NOT INSTALLED")
echo -n "pip-audit: " && (which pip-audit && pip-audit --version 2>/dev/null || echo "NOT INSTALLED")
echo -n "snyk:      " && (which snyk && snyk --version 2>/dev/null || echo "NOT INSTALLED")
echo -n "trivy:     " && (which trivy && trivy --version 2>/dev/null || echo "NOT INSTALLED")
```

---

## Running a Full Scan

Once tools are installed, run each against your target:

```bash
TARGET=/path/to/project

echo "=== Running semgrep ==="
semgrep scan --config auto "$TARGET" --json > /tmp/semgrep.json 2>/dev/null

echo "=== Running bandit ==="
bandit -r "$TARGET" -f json -ll > /tmp/bandit.json 2>/dev/null || true

echo "=== Running dependency audits ==="
cd "$TARGET"
[ -f requirements.txt ] && pip-audit --format json > /tmp/pip_audit.json 2>/dev/null || true
[ -f package.json ] && npm audit --json > /tmp/npm_audit.json 2>/dev/null || true

echo "=== Running trivy filesystem scan ==="
trivy fs --format json "$TARGET" > /tmp/trivy.json 2>/dev/null || true

echo "=== Scan complete ==="
ls -la /tmp/*json
```

Results are saved as JSON files in `/tmp/` and can be used by the Cybersecurity Audit Skill to merge findings into the final report.
