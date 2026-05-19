---
name: cybersecurity-audit
description: >
  Full-spectrum security audit for any project — SAST, DAST, SCA, secret scanning,
  IaC security, container hardening, IAM/RBAC review, threat modeling, and API security.
  Step-by-step investigation with context-gathering questions before scanning.
  Produces triage findings, autofix patches, and a structured report.
triggers:
  - "audit this app / codebase / repo"
  - "find security vulnerabilities"
  - "run a security scan"
  - "SAST / DAST / SCA / static analysis"
  - "security review before deploy"
  - "pentest / vulnerability assessment"
  - "scan this project for security issues"
  - "check security of this code"
  - "DevSecOps audit"
  - "cloud security review"
  - "scan a project"
---

# Cybersecurity Audit Skill

## Philosophy

This is a **step-by-step investigation**, not a one-shot scan.
Before running any tool, gather context. Ask what you don't know.
A security audit without context produces noise, not signal.

---

## PHASE 0 — Context Gathering (ALWAYS run this first)

Before touching any tool or scanning any file, ask the following questions.
**Only skip a question if the answer is already visible in the conversation or codebase.**

### 0.1 — Mandatory Context Questions

Ask ALL of these before proceeding to Phase 1:

1. **Stack** — What languages and frameworks does this project use?
   *(Python/Flask, Node/Express, Go, React, Java Spring, etc.)*

2. **Infrastructure** — Where does this run?
   *(AWS / GCP / Azure / on-prem / Docker / Kubernetes / serverless)*

3. **Entry points** — What are the main attack surfaces?
   *(REST API, GraphQL, web app, CLI tool, background jobs, webhooks)*

4. **Auth model** — How does authentication and authorization work?
   *(JWT, OAuth2, session cookies, API keys, RBAC, ABAC, no auth yet)*

5. **Data sensitivity** — What kind of data does this handle?
   *(PII, financial, health/PHI, credentials, public data only)*

6. **Compliance requirements** — Any regulatory frameworks in scope?
   *(PCI-DSS, SOC2, ISO 27001, HIPAA, LGPD, GDPR, none)*

7. **Deployment pipeline** — How is code deployed?
   *(GitHub Actions, Jenkins, GitLab CI, manual, IaC with Terraform/Pulumi)*

8. **Previous audits** — Any known issues or prior security reviews?
   *(Known CVEs, previous pentest findings, "we know about X but haven't fixed it")*

### 0.2 — Conditional Context Questions

Ask ONLY if relevant based on answers above:

- **Containers?** → What base images? Docker Hub or private registry? rootless?
- **Secrets management?** → .env files? AWS Secrets Manager? Vault? Hardcoded?
- **Third-party integrations?** → Webhooks, OAuth providers, payment gateways?
- **Public-facing?** → Is this internet-exposed or internal only?
- **Monorepo?** → Which subdirectory is in scope?

### 0.3 — Scope Confirmation

After gathering context, confirm scope with the user:
> "Based on what you've told me, I'll audit: [list scope]. I'll check:
> [list of applicable audit layers]. Does that sound right, or should I add/remove anything?"

---

## PHASE 1 — Threat Modeling (BEFORE any tool runs)

A security audit without a threat model is just a checklist. Threat modeling answers:
**"What are we protecting, from whom, and what are the most likely attack paths?"**

### 1.1 — Define Scope & Assets

Identify and document:
- **Crown jewels** — What data/functionality, if compromised, would cause the most damage?
  *(user PII, payment data, admin credentials, source code, encryption keys)*
- **Trust boundaries** — Where does data cross from one trust zone to another?
  *(internet → API gateway → service → database → external API)*
- **Entry points** — All ways an attacker can interact with the system
  *(login form, API endpoints, webhooks, file uploads, background jobs, admin panels)*
- **Actors** — Who uses the system and at what privilege level?
  *(anonymous user, authenticated user, admin, internal service, external partner)*

### 1.2 — Data Flow Diagram (DFD)

Draw or describe the Level-0 and Level-1 DFDs. For each data flow, note:
- What data crosses the boundary?
- Is it encrypted in transit?
- Is it authenticated?
- Is it logged?

If no DFD exists, generate one from the codebase:
```bash
# Find all HTTP client calls (outbound data flows)
grep -rn "requests\.\|axios\.\|fetch(\|http\.\|https\." . --include="*.py" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v ".audit"

# Find all database connections (data stores)
grep -rn "connect\|createPool\|mongoose\|sqlalchemy\|prisma\|sequelize" . --include="*.py" --include="*.js" --include="*.ts" | grep -v node_modules
```

### 1.3 — STRIDE Analysis

Apply STRIDE to every component and trust boundary crossing:

| Threat | Stands For | Question to ask | Example |
|---|---|---|---|
| **S** | Spoofing | Can an attacker impersonate a user or service? | Forged JWT, stolen API key |
| **T** | Tampering | Can data be modified in transit or at rest? | Missing integrity checks, writable config |
| **R** | Repudiation | Can actions be denied? Is there an audit trail? | No logging on sensitive ops |
| **I** | Information Disclosure | Can sensitive data leak? | Verbose errors, unencrypted fields |
| **D** | Denial of Service | Can the system be made unavailable? | No rate limits, unbounded queries |
| **E** | Elevation of Privilege | Can a low-priv user gain higher access? | IDOR, missing RBAC checks |

**STRIDE worksheet — fill in per component:**
```
Component: [API Gateway / Auth Service / DB / etc.]
S — Spoofing threat: [describe] | Control: [existing] | Gap: [missing]
T — Tampering threat: [describe] | Control: [existing] | Gap: [missing]
R — Repudiation threat: [describe] | Control: [existing] | Gap: [missing]
I — Info Disclosure threat: [describe] | Control: [existing] | Gap: [missing]
D — DoS threat: [describe] | Control: [existing] | Gap: [missing]
E — EoP threat: [describe] | Control: [existing] | Gap: [missing]
```

### 1.4 — Attack Tree (Top 3 Scenarios)

For each high-value target, build an attack tree:

```
Goal: Steal user PII
├── Path A: SQL Injection
│   ├── Find injectable endpoint (SAST/manual)
│   └── Exfiltrate via UNION SELECT
├── Path B: Authentication Bypass
│   ├── Brute-force login (no rate limit)
│   ├── JWT algorithm confusion (alg: none)
│   └── Password reset flow abuse
└── Path C: Insider / Supply Chain
    ├── Compromised dependency (SCA)
    └── Leaked DB credentials in git history (secret scan)
```

Create attack trees for your top 3 scenarios before scanning. This focuses the audit on real risk paths.

### 1.5 — PASTA (optional — for high-risk / compliance projects)

Process for Attack Simulation and Threat Analysis — 7 stages:
1. Define business objectives & security requirements
2. Define technical scope (DFDs, asset inventory)
3. Application decomposition (entry points, data flows, trust boundaries)
4. Threat analysis (threat actors, TTPs from MITRE ATT&CK)
5. Vulnerability & weakness analysis (link to SAST/SCA findings)
6. Attack modeling (attack trees per threat)
7. Risk & impact analysis (prioritized residual risk)

Save threat model output to: `.audit/threat-model-YYYY-MM-DD.md`

---

## PHASE 2 — Tooling Setup

### 1.1 — Install SAST/SCA tools (based on detected stack)

```bash
# Universal
pip install semgrep

# Python projects
pip install bandit pip-audit

# Node.js projects
npm install -g njsscan
npx npm audit  # built-in, no install needed

# Secret scanning (all projects)
pip install detect-secrets
# OR
brew install gitleaks  # macOS
# OR download gitleaks binary for Linux:
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz

# IaC scanning
pip install checkov

# Container scanning
# Install trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Dependency graph / SBOM
pip install cyclonedx-bom  # Python SBOM
npm install -g @cyclonedx/cyclonedx-npm  # Node SBOM
```

Add to PATH if needed:
```bash
export PATH=$PATH:~/.local/bin
```

### 1.2 — Create output directory

```bash
mkdir -p .audit/{sast,sca,secrets,iac,containers,api,manual}
```

---

## PHASE 2 — Multi-Layer Audit Execution

Run ALL applicable layers based on project context. Skip layers that don't apply.

---

### Layer 1 — SAST (Static Application Security Testing)

**Purpose:** Find code-level vulnerabilities — injections, XSS, insecure APIs, weak crypto.

```bash
# Python
bandit -r ./src -f json -o .audit/sast/bandit.json
semgrep --config=p/python --config=p/owasp-top-ten ./src --json > .audit/sast/semgrep-python.json

# Node.js / JavaScript / TypeScript
njsscan ./src --json > .audit/sast/njsscan.json
semgrep --config=p/javascript --config=p/nodejs --config=p/typescript ./src --json > .audit/sast/semgrep-node.json

# Go
semgrep --config=p/golang ./src --json > .audit/sast/semgrep-go.json

# Java
semgrep --config=p/java ./src --json > .audit/sast/semgrep-java.json

# React / frontend
semgrep --config=p/react --config=p/xss ./src --json > .audit/sast/semgrep-react.json

# General (all languages)
semgrep --config=p/owasp-top-ten . --json > .audit/sast/semgrep-owasp.json
```

**What to look for:**
- SQL/NoSQL/command/LDAP injection (CWE-89, CWE-78, CWE-90)
- XSS — reflected, stored, DOM-based (CWE-79)
- Path traversal (CWE-22)
- Insecure deserialization (CWE-502)
- Hardcoded secrets in source (CWE-798)
- Weak cryptography — MD5, SHA1, Math.random (CWE-327, CWE-330)
- SSRF (CWE-918)
- Open redirect (CWE-601)
- Race conditions (CWE-362)
- Missing input validation (CWE-20)

---

### Layer 2 — SCA (Software Composition Analysis)

**Purpose:** Find vulnerabilities in third-party dependencies.

```bash
# Python
pip-audit --output json > .audit/sca/pip-audit.json
# OR
safety check --json > .audit/sca/safety.json

# Node.js
npm audit --json > .audit/sca/npm-audit.json

# Generate SBOM
pip install cyclonedx-bom && cyclonedx-py -o .audit/sca/sbom-python.json
```

**What to look for:**
- Known CVEs in direct and transitive dependencies
- Outdated packages with security patches available
- Packages with no maintainer / abandoned
- License compliance issues

---

### Layer 3 — Secret Scanning

**Purpose:** Find credentials, API keys, tokens committed to the codebase (current or history).

```bash
# Scan current working tree
detect-secrets scan . > .audit/secrets/detect-secrets-baseline.json
detect-secrets audit .audit/secrets/detect-secrets-baseline.json

# Scan git history (catches deleted secrets)
gitleaks detect --source . --report-path .audit/secrets/gitleaks.json --report-format json

# Manual grep patterns (belt + suspenders)
grep -rn "password\s*=\s*['\"]" . --include="*.py" --include="*.js" --include="*.ts" --include="*.env" | grep -v ".audit"
grep -rn "api_key\|secret_key\|access_token\|private_key" . --include="*.py" --include="*.js" --include="*.yaml" | grep -v ".audit"
```

**High-priority patterns to manually check:**
- `.env` files committed (should be in .gitignore)
- AWS credentials (`AKIA...`)
- Private keys (`-----BEGIN RSA PRIVATE KEY-----`)
- Database connection strings with embedded passwords
- JWT secrets hardcoded in source

---

### Layer 4 — IaC Security (Infrastructure as Code)

**Purpose:** Find misconfigurations in Terraform, CloudFormation, Kubernetes, Helm, Docker.

```bash
# Terraform / CloudFormation / Kubernetes / Dockerfile / Helm
checkov -d . --output json > .audit/iac/checkov.json

# Kubernetes-specific
checkov -d ./k8s --framework kubernetes --output json > .audit/iac/checkov-k8s.json

# Dockerfile
checkov -d . --framework dockerfile --output json > .audit/iac/checkov-docker.json
```

**What to look for:**
- Public S3 buckets / storage (CWE-200)
- Security groups open to 0.0.0.0/0 on sensitive ports
- Missing encryption at rest / in transit
- Root IAM users with access keys
- Missing MFA enforcement
- Missing CloudTrail / audit logging
- Overly permissive IAM policies (wildcard `*` actions)
- Containers running as root
- Missing resource limits (CPU/memory)
- Exposed Kubernetes dashboards / APIs
- Missing network policies

---

### Layer 5 — Container Security

**Purpose:** Find vulnerabilities in container images and runtime configurations.

```bash
# Scan container image for CVEs
trivy image <image-name>:<tag> --format json > .audit/containers/trivy-image.json

# Scan Dockerfile for misconfigurations
trivy config ./Dockerfile --format json > .audit/containers/trivy-dockerfile.json

# Scan entire project (IaC + containers)
trivy fs . --format json > .audit/containers/trivy-fs.json
```

**What to look for:**
- Base image with known CVEs (use slim/distroless images)
- Running as root inside container
- Exposed secrets via ENV in Dockerfile
- No HEALTHCHECK defined
- Writable root filesystem (should be read-only)
- Privileged mode enabled
- Missing USER instruction (defaults to root)

---

### Layer 6 — API Security Review

**Purpose:** Manually review API design for OWASP API Top 10 issues.

If an OpenAPI/Swagger spec exists:
```bash
# Find spec files
find . -name "openapi*.yaml" -o -name "swagger*.yaml" -o -name "openapi*.json" 2>/dev/null

# Install spectral for OpenAPI linting
npm install -g @stoplight/spectral-cli
spectral lint openapi.yaml --ruleset @stoplight/spectral-owasp-ruleset
```

**Manual review checklist — OWASP API Top 10:**
- [ ] **API1** — Broken Object Level Authorization (BOLA/IDOR): Does every endpoint verify the caller owns the resource?
- [ ] **API2** — Broken Authentication: Missing auth on endpoints? Weak token validation?
- [ ] **API3** — Broken Object Property Level Auth: Can users read/write fields they shouldn't?
- [ ] **API4** — Unrestricted Resource Consumption: Rate limiting? Pagination limits? File size limits?
- [ ] **API5** — Broken Function Level Authorization: Can non-admins call admin endpoints?
- [ ] **API6** — Unrestricted Access to Sensitive Business Flows: Abuse-prone flows (mass registration, bulk discount abuse)?
- [ ] **API7** — SSRF: Does the API fetch user-supplied URLs?
- [ ] **API8** — Security Misconfiguration: Verbose errors? Debug mode on? CORS wildcard?
- [ ] **API9** — Improper Inventory Management: Undocumented/shadow endpoints? Old API versions still live?
- [ ] **API10** — Unsafe Consumption of APIs: Trusting external API responses without validation?

---

### Layer 7 — Authentication & Authorization Deep Dive

**Purpose:** Review auth architecture for design flaws that tools can't detect.

**Manual review checklist:**

**Authentication:**
- [ ] Password hashing: bcrypt/argon2/scrypt (not MD5/SHA1)
- [ ] JWT: algorithm forced to RS256/ES256 (not `alg: none` or HS256 with weak secret)
- [ ] JWT expiry: short-lived access tokens (<15 min) + refresh token rotation
- [ ] Session fixation: new session ID generated on login
- [ ] Brute-force protection: rate limiting + lockout on failed logins
- [ ] MFA available for sensitive operations
- [ ] Secure cookie flags: HttpOnly, Secure, SameSite=Strict
- [ ] Password reset: token single-use + expiry + no user enumeration

**Authorization:**
- [ ] Every endpoint checks identity before authorization
- [ ] RBAC/ABAC enforced server-side (never trust client-sent role)
- [ ] Object-level ownership check on every resource access (IDOR prevention)
- [ ] Principle of least privilege applied to service accounts
- [ ] No hidden admin endpoints accessible without auth
- [ ] Audit log for all privilege escalation events

---

### Layer 8 — DAST (Dynamic Application Security Testing)

**Purpose:** Test the *running* application — finds vulnerabilities that SAST never sees: runtime auth bypass, session handling flaws, header misconfigs, injection via actual HTTP traffic.

**Prerequisite:** The application must be running (locally or in a test environment). Never run DAST against production without explicit authorization.

```bash
# Start the target app first, note the URL (e.g. http://localhost:5000)
TARGET_URL="http://localhost:5000"

# --- Option A: OWASP ZAP (most comprehensive) ---
# Pull ZAP Docker image
docker pull ghcr.io/zaproxy/zaproxy:stable

# Baseline scan (passive — no active attack, safe for any env)
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t $TARGET_URL \
  -r .audit/dast/zap-baseline.html \
  -J .audit/dast/zap-baseline.json

# Full active scan (finds injections, auth bypass, XSS — use on test env only)
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t $TARGET_URL \
  -r .audit/dast/zap-full.html \
  -J .audit/dast/zap-full.json

# API scan (if OpenAPI/Swagger spec available)
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t $TARGET_URL/openapi.json \
  -f openapi \
  -r .audit/dast/zap-api.html

# --- Option B: Nuclei (template-based, fast, great for APIs) ---
# Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# OR
brew install nuclei

# Run against target with CVE + misconfiguration + exposure templates
nuclei -u $TARGET_URL \
  -t cves/ -t misconfigurations/ -t exposures/ -t vulnerabilities/ \
  -severity critical,high,medium \
  -json -o .audit/dast/nuclei.json

# --- Option C: Nikto (quick web server misconfiguration scan) ---
nikto -h $TARGET_URL -Format json -output .audit/dast/nikto.json
# If not installed:
apt-get install nikto -y
```

**What DAST finds that SAST misses:**
- Authentication bypass on running endpoints
- Session tokens not invalidated on logout
- Missing or misconfigured security headers at runtime
- Server-side request forgery via live HTTP calls
- Directory listing / path disclosure
- Default credentials on admin panels
- Clickjacking (missing X-Frame-Options)
- Mixed content (HTTP resources on HTTPS page)
- Real XSS that executes in browser context
- Insecure HTTP methods (PUT/DELETE/TRACE enabled)
- Version disclosure in server response headers

**DAST Rules:**
- ⚠️ Always get **written authorization** before running active DAST scans
- Only run active scans against **dedicated test environments**
- Never run ZAP full-scan or Nuclei against production
- Baseline/passive scans are safe for staging environments

---

### Layer 9 — Manual Code Review (Targeted)

**Purpose:** Review the most sensitive code paths that automated tools miss.

Focus on these files/patterns:
```bash
# Find auth-related files
find . -name "auth*" -o -name "*middleware*" -o -name "*token*" -o -name "*session*" 2>/dev/null | grep -v node_modules | grep -v ".audit"

# Find database query files
find . -name "*model*" -o -name "*repository*" -o -name "*dao*" -o -name "*query*" 2>/dev/null | grep -v node_modules

# Find file upload handlers
grep -rn "upload\|multipart\|formdata\|multer\|flask.*file" . --include="*.py" --include="*.js" --include="*.ts" | grep -v node_modules

# Find eval / exec usage
grep -rn "eval\|exec\|os\.system\|subprocess.*shell=True\|child_process" . --include="*.py" --include="*.js" --include="*.ts" | grep -v node_modules
```

**Manual review focus areas:**
- File upload handlers (path traversal, MIME type bypass, malicious content)
- Cryptographic implementations (DIY crypto is always wrong)
- Business logic flaws (price manipulation, workflow bypass, race conditions)
- Error handling (stack traces leaking to users, verbose error messages)
- Logging (are passwords/tokens being logged?)
- Third-party library usage (are unsafe methods being called?)

---

### Layer 10 — Supply Chain Security

**Purpose:** After SolarWinds, XZ Utils, and log4shell — the build pipeline and dependency chain are attack surfaces as critical as the app itself.

```bash
# --- Dependency Integrity ---
# Check for dependency confusion attacks (internal package names on public registries)
# Look for packages in requirements.txt / package.json that match internal naming patterns
cat requirements.txt | grep -v "^#" | grep -v "^$"
cat package.json | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k) for k in d.get('dependencies',{}).keys()]"

# Verify dependency hashes are pinned (requirements.txt should use ==, not >=)
grep ">=" requirements.txt && echo "WARNING: unpinned dependencies found"

# Check for floating tags in package.json (^ and ~ allow unexpected updates)
grep '"\^' package.json && echo "WARNING: caret ranges allow minor version drift"

# --- SBOM Generation & Attestation ---
# Python SBOM
pip install cyclonedx-bom
cyclonedx-py -o .audit/sca/sbom-python.json

# Node SBOM
npx @cyclonedx/cyclonedx-npm --output-file .audit/sca/sbom-node.json

# Verify SBOM components against OSV vulnerability database
pip install osv-scanner 2>/dev/null || go install github.com/google/osv-scanner/cmd/osv-scanner@v1
osv-scanner --sbom .audit/sca/sbom-python.json --json > .audit/sca/osv-results.json

# --- Git Commit Signing ---
# Check if commits are GPG-signed
git log --show-signature --oneline | head -20
git log --format="%G? %H %s" | head -20
# G = good signature, N = no signature, U = unknown key, B = bad signature

# Check if branch protection requires signed commits
# (GitHub: Settings → Branches → require signed commits)

# --- CI/CD Pipeline Security Review ---
# Find all CI configuration files
find . -name "*.yml" -path "*/.github/workflows/*" \
     -o -name "*.yaml" -path "*/.github/workflows/*" \
     -o -name "Jenkinsfile" \
     -o -name ".gitlab-ci.yml" \
     -o -name ".circleci/config.yml" 2>/dev/null | grep -v node_modules

# Check for dangerous patterns in CI
grep -rn "eval\|curl.*|\|wget.*|" .github/workflows/ .gitlab-ci.yml Jenkinsfile 2>/dev/null
grep -rn "secrets\." .github/workflows/ 2>/dev/null  # how secrets are referenced
grep -rn "pull_request_target" .github/workflows/ 2>/dev/null  # dangerous event

# --- Artifact Signing (Sigstore/cosign) ---
# Check if container images are signed
cosign verify <image>:<tag> --certificate-identity-regexp=".*" --certificate-oidc-issuer-regexp=".*" 2>/dev/null || echo "Image not signed"
```

**Supply Chain Security Checklist:**
- [ ] All dependencies pinned to exact versions (not ranges)
- [ ] Dependency hashes verified (`pip install --require-hashes`, `npm ci`)
- [ ] No internal package names exposed on public registries (dependency confusion)
- [ ] SBOM generated and stored with each release
- [ ] Git commits GPG-signed by all contributors
- [ ] Branch protection: require PR reviews + signed commits + passing CI
- [ ] CI/CD secrets stored in vault (not hardcoded in pipeline files)
- [ ] `pull_request_target` + `actions/checkout` with user code = critical risk
- [ ] Container images signed with Sigstore/cosign
- [ ] Dependabot or Renovate enabled for automatic dependency updates
- [ ] Third-party GitHub Actions pinned to commit SHA (not tag)
- [ ] Artifact provenance tracked (SLSA level 2+ recommended)

Save to: `.audit/supply-chain-YYYY-MM-DD.md`

---

### Layer 11 — Security Headers & TLS

**Purpose:** Validate transport security and browser-level defenses that protect users from MITM, clickjacking, XSS, and data interception.

```bash
TARGET_URL="https://yourdomain.com"  # Must be the live URL

# --- testssl.sh (comprehensive TLS/SSL analysis) ---
# Install
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
# OR: brew install testssl

/opt/testssl/testssl.sh --jsonfile .audit/headers/testssl.json $TARGET_URL

# --- sslyze (Python TLS scanner) ---
pip install sslyze
python -m sslyze $TARGET_URL --json_out .audit/headers/sslyze.json

# --- Security Headers check (curl-based) ---
curl -sI $TARGET_URL | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|cache-control"

# --- Check for info-leaking headers ---
curl -sI $TARGET_URL | grep -iE "server:|x-powered-by:|x-aspnet-version:|x-runtime:"
```

**Security Headers Checklist:**

| Header | Required Value | Risk if Missing |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | MITM, SSL stripping |
| `Content-Security-Policy` | Explicit allowlist (no `unsafe-inline`) | XSS |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Data leakage in Referer |
| `Permissions-Policy` | Restrict camera/mic/geolocation | Feature abuse |
| `Cache-Control` | `no-store` on auth/sensitive endpoints | Credential caching |

**Headers that must NOT appear (info leakage):**
- `Server: Apache/2.4.51` — reveals version
- `X-Powered-By: Express` — reveals framework
- `X-AspNet-Version` — reveals .NET version
- `X-Runtime` — reveals response time (timing attacks)

**TLS Checklist:**
- [ ] TLS 1.0 and 1.1 disabled
- [ ] TLS 1.2 minimum, TLS 1.3 preferred
- [ ] No weak cipher suites (RC4, DES, 3DES, EXPORT)
- [ ] Certificate valid + not expiring within 30 days
- [ ] Certificate chain complete (no intermediate cert missing)
- [ ] HSTS enabled with preload
- [ ] OCSP stapling enabled
- [ ] No mixed content (HTTP resources on HTTPS page)
- [ ] Certificate pinning implemented (mobile apps)

**Automated online check (for public endpoints):**
```
https://securityheaders.com/?q=<domain>&followRedirects=on
https://www.ssllabs.com/ssltest/analyze.html?d=<domain>
```
Target grade: **A or A+** on both.

Save to: `.audit/headers/headers-review-YYYY-MM-DD.md`

---

## PHASE 3 — Triage & Classification

### 3.1 — Finding Schema

Every finding must have:
```json
{
  "id": "CRIT-001",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "category": "Injection | Auth | Crypto | Config | Secrets | Dependency | IaC | Container | API",
  "cwe": "CWE-89",
  "owasp": "A03:2021",
  "file": "src/app.py",
  "line": 42,
  "description": "SQL query built with string concatenation allows injection",
  "evidence": "query = f'SELECT * FROM users WHERE id = {user_id}'",
  "impact": "Full database read/write access",
  "recommendation": "Use parameterized queries",
  "autofix_ready": true,
  "status": "open"
}
```

### 3.2 — Risk Score Calculation

```
Risk Score = min(100, Σ weights)
  CRITICAL = 25 pts each
  HIGH     = 10 pts each
  MEDIUM   =  3 pts each
  LOW      =  1 pt  each

0–19   → GREEN  (low risk)
20–49  → YELLOW (moderate risk)
50–79  → ORANGE (high risk)
80–100 → RED    (critical — do not deploy)
```

### 3.3 — Output file

Save to: `.audit/findings-YYYY-MM-DD.json`

---

## PHASE 4 — Autofix Pass

Prioritize `autofix_ready: true` findings. Apply fixes, then re-run the relevant tool to verify.

### Common Fix Patterns

| Vulnerability | CWE | Bad | Fixed |
|---|---|---|---|
| SQL injection | CWE-89 | `f"SELECT...{user_id}"` | `cursor.execute("SELECT... WHERE id=?", (user_id,))` |
| Command injection | CWE-78 | `os.system(cmd)` | `subprocess.run(cmd.split(), check=True)` |
| XSS | CWE-79 | `return f"<h1>{name}</h1>"` | `return jsonify({"name": name})` |
| Path traversal | CWE-22 | `open(user_path)` | `safe = os.path.realpath(user_path); assert safe.startswith(BASE_DIR)` |
| Hardcoded secret | CWE-798 | `SECRET = "abc123"` | `SECRET = os.environ.get("SECRET_KEY")` |
| Weak crypto | CWE-327 | `hashlib.md5(pw)` | `bcrypt.hashpw(pw, bcrypt.gensalt())` |
| Insecure random | CWE-330 | `random.randint()` | `secrets.token_hex(32)` |
| Deserialization | CWE-502 | `pickle.loads(data)` | `json.loads(data)` |
| CORS wildcard | CWE-942 | `CORS(app, origins="*")` | `CORS(app, origins=["https://yourdomain.com"])` |
| SSRF | CWE-918 | `requests.get(user_url)` | validate URL against allowlist + block private ranges |
| Exposed debug | CWE-94 | `app.run(debug=True)` | `app.run(debug=os.environ.get("DEBUG","false")=="true")` |
| Missing rate limit | CWE-400 | no limiter | `@limiter.limit("10/minute")` |

**Cannot autofix (require architectural decisions):**
- Broken auth / missing auth (CWE-287, CWE-306) → implement JWT/session auth
- IDOR / broken object auth (CWE-639) → add ownership checks tied to identity
- CSRF (CWE-352) → implement token-based CSRF protection
- Business logic flaws → require design review

---

## PHASE 8 — Cloud IAM Deep Dive

**Purpose:** Overly permissive IAM is the #1 cause of cloud breaches. Static IaC scanning (Checkov) only sees what's in code — this phase analyzes the *live* cloud configuration including privilege escalation paths, unused credentials, and cross-account trust.

### 8.1 — Multi-Cloud Scanner (Prowler)

```bash
pip install prowler

# AWS — comprehensive posture assessment
prowler aws \
  --output-formats json html \
  --output-directory .audit/cloud-iam/ \
  --compliance cis_aws_3.0.0

# GCP
prowler gcp --output-formats json --output-directory .audit/cloud-iam/

# Azure
prowler azure --output-formats json --output-directory .audit/cloud-iam/
```

### 8.2 — ScoutSuite (Multi-cloud Security Auditing)

```bash
pip install scoutsuite
scout aws --report-dir .audit/cloud-iam/scoutsuite --no-browser
scout gcp --report-dir .audit/cloud-iam/scoutsuite --user-account
scout azure --cli --report-dir .audit/cloud-iam/scoutsuite
```

### 8.3 — AWS IAM Analysis

```bash
# Credential report — all users + last activity
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > .audit/cloud-iam/iam-credentials.csv

# Find stale credentials (>90 days inactive)
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  python3 -c "
import csv, sys, datetime
for row in csv.DictReader(sys.stdin):
    last = row.get('password_last_used','N/A')
    if last not in ['N/A','no_information','not_supported']:
        try:
            d = datetime.datetime.fromisoformat(last.replace('Z','+00:00'))
            age = (datetime.datetime.now(datetime.timezone.utc) - d).days
            if age > 90: print(f'STALE ({age}d): {row[\"user\"]}')
        except: pass
"

# Find wildcard * policies (overly permissive)
aws iam list-policies --scope Local --output json | \
  python3 -c "import json,sys; [print(p['PolicyName']) for p in json.load(sys.stdin)['Policies']]"
```

**IAM Security Checklist:**
- [ ] Root account has no access keys
- [ ] Root account MFA enabled
- [ ] All IAM users have MFA enabled
- [ ] No users with both console + programmatic access (separate them)
- [ ] Access keys rotated within 90 days
- [ ] Stale credentials (>90d inactive) disabled
- [ ] No wildcard `*` actions in customer-managed policies
- [ ] Principle of least privilege — roles scoped to specific resources
- [ ] Cross-account trust relationships documented and reviewed
- [ ] CloudTrail enabled in all regions with log integrity
- [ ] GuardDuty enabled
- [ ] IAM Access Analyzer enabled

**Critical Privilege Escalation Paths to check:**
- `iam:CreatePolicyVersion` → create new version with `*` permissions
- `iam:AttachUserPolicy` → attach `AdministratorAccess` to self
- `iam:PassRole` + `ec2:RunInstances` → launch EC2 with admin role
- `sts:AssumeRole` with overly broad trust policy
- Lambda + `iam:PassRole` → function with elevated role
- `iam:CreateAccessKey` on another user → credential takeover

Save to: `.audit/cloud-iam/iam-review-YYYY-MM-DD.md`

---

## PHASE 9 — Mobile & Frontend Security

**Purpose:** Mobile apps and SPAs have unique attack vectors — local storage exposure, certificate trust, deep link hijacking, reverse engineering. The CISO profile explicitly lists mobile pentests as a core daily activity.

### 9.1 — React / SPA Security

```bash
# Semgrep rules for React-specific issues
semgrep --config=p/react --config=p/xss --config=p/javascript ./src --json > .audit/sast/semgrep-react.json

# Find dangerous React patterns
grep -rn "dangerouslySetInnerHTML" ./src --include="*.jsx" --include="*.tsx"
grep -rn "eval\|Function(" ./src --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "localStorage\.\|sessionStorage\." ./src --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "document\.cookie" ./src --include="*.js" --include="*.ts"
```

**Frontend Security Checklist:**
- [ ] No sensitive data stored in `localStorage` or `sessionStorage` (use httpOnly cookies)
- [ ] No `dangerouslySetInnerHTML` with user-controlled data
- [ ] CSP header blocks inline scripts and unsafe-eval
- [ ] No API keys or secrets in frontend JavaScript bundles
- [ ] Source maps not served in production (exposes original source)
- [ ] Third-party scripts loaded only from trusted CDNs with SRI hashes
- [ ] `window.postMessage` validates origin before processing
- [ ] No sensitive data in URL parameters (logged by servers/proxies)

```bash
# Check for secrets in JS bundles (built output)
find ./dist ./build -name "*.js" 2>/dev/null | xargs grep -l "apiKey\|secret\|password\|token" 2>/dev/null

# Check SRI hashes on external scripts in HTML
grep -rn "<script src=" ./public ./dist 2>/dev/null | grep -v "integrity="
```

### 9.2 — Mobile App Security (iOS/Android)

**If APK available:**
```bash
# Install MobSF (Mobile Security Framework)
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Upload APK/IPA via browser: http://localhost:8000
# Or via API:
curl -F "file=@app.apk" http://localhost:8000/api/v1/upload \
  -H "Authorization: $(curl -s http://localhost:8000/api/v1/api_docs | python3 -c 'import json,sys; print(json.load(sys.stdin).get("apikey",""))')"
```

**Mobile Security Checklist:**
- [ ] Certificate pinning implemented (prevents MITM with custom CA)
- [ ] No sensitive data in `SharedPreferences` / `NSUserDefaults` unencrypted
- [ ] No sensitive data in app logs (`logcat` / `NSLog`)
- [ ] No hardcoded API keys, secrets, or credentials in APK/IPA
- [ ] Root/jailbreak detection implemented (for sensitive apps)
- [ ] App transport security enforced (no HTTP cleartext)
- [ ] Deep links validate the calling app before processing
- [ ] Backup flag disabled (Android: `android:allowBackup="false"`)
- [ ] No debug flags in production build (`android:debuggable="false"`)
- [ ] Biometric auth + fallback uses secure storage (Keystore/Secure Enclave)

Save to: `.audit/mobile-frontend-YYYY-MM-DD.md`

---

### 5.2 — Remediation Roadmap (30/60/90-day plan)

A professional audit doesn't just list findings — it delivers a **prioritized action plan** with business context, effort estimates, and timelines that engineering leadership can act on immediately.

```markdown
## Remediation Roadmap — [Project Name]
Generated: YYYY-MM-DD | Risk Score: XX/100 → [RED/ORANGE/YELLOW/GREEN]

### 🔴 IMMEDIATE — Fix before next deploy (Day 0–7)
| # | Finding | CWE | Effort | Owner | Business Risk |
|---|---|---|---|---|---|
| 1 | SQL Injection in /api/users | CWE-89 | 2h | Backend team | Full DB compromise |
| 2 | Hardcoded AWS key in config.py | CWE-798 | 30m | DevOps | Cloud account takeover |

### 🟠 30-Day Sprint
| # | Finding | CWE | Effort | Owner | Business Risk |
|---|---|---|---|---|---|
| 3 | Missing rate limiting on /login | CWE-400 | 4h | Backend | Credential brute-force |
| 4 | JWT using HS256 with weak secret | CWE-327 | 3h | Backend | Session forgery |

### 🟡 60-Day Sprint
| # | Finding | CWE | Effort | Owner | Business Risk |
|---|---|---|---|---|---|
| 5 | CORS wildcard on API | CWE-942 | 1h | Backend | Cross-origin data theft |
| 6 | Missing HSTS header | — | 30m | DevOps | SSL stripping |

### 🟢 90-Day Backlog
| # | Finding | CWE | Effort | Owner | Business Risk |
|---|---|---|---|---|---|
| 7 | Broken auth architecture (no RBAC) | CWE-284 | 2 weeks | Arch team | Horizontal privilege escalation |
| 8 | No incident response runbook | — | 3d | SecOps | Blind to breaches |

### Effort Key
- XS = <1h | S = 1-4h | M = 1-2d | L = 1 week | XL = >1 week

### Accepted Risks (documented + signed off)
| Finding | Risk Owner | Rationale | Review Date |
|---|---|---|---|
| Self-signed cert on internal API | CTO | Internal only, no external exposure | YYYY-MM-DD |
```

### 5.3 — Report structure

`.audit/report-YYYY-MM-DD.md`:

```markdown
# Security Audit Report — [Project Name]
**Date:** YYYY-MM-DD
**Auditor:** [name]
**Audit Type:** Full-spectrum (SAST + DAST + SCA + IaC + Cloud IAM + Supply Chain + Headers)
**Scope:** [what was audited — see Scope Exclusions section]
**Risk Score:** XX/100 → [GREEN/YELLOW/ORANGE/RED]
**IR Readiness Score:** XX/100

## Executive Summary
[3-5 sentences: total findings, most critical issue, immediate action required, compliance impact]

## Risk Score Breakdown
[Pie/table by severity — CRITICAL N, HIGH N, MEDIUM N, LOW N]

## Top 5 Findings (Executive View)
[Each: title, one-sentence impact, one-sentence fix, business risk]

## Findings by Severity (Technical Detail)
[Full finding list with evidence and recommendations]

## Remediation Roadmap
[30/60/90-day table — see 5.2]

## What Was Fixed This Session
[Table: finding ID, what was fixed, verified by]

## Scope Exclusions
[See Phase 10]

## Compliance Mapping
[Findings mapped to PCI-DSS / ISO 27001 / SOC2 controls]

## Next Steps
[Retest date, who owns what, escalation path]
```

---

## PHASE 10 — Evidence Collection

**Purpose:** Findings without evidence get disputed or deprioritized. Professional-grade audits document every finding with reproducible proof.

### 10.1 — Evidence Standards per Severity

**CRITICAL findings require:**
- [ ] HTTP request + response captured (curl command or Burp Suite export)
- [ ] Proof-of-concept (PoC) code or payload that reproduces the issue
- [ ] Screenshot of the exploited condition (if visual)
- [ ] Impact statement: what data/access is exposed if exploited

**HIGH findings require:**
- [ ] Relevant code snippet with line number
- [ ] Tool output that identified the issue (Semgrep/Bandit finding JSON)
- [ ] Brief description of exploitation path

**MEDIUM/LOW findings require:**
- [ ] Code snippet or config excerpt
- [ ] Tool finding reference

### 10.2 — Evidence Collection Commands

```bash
# Capture HTTP request/response (curl verbose)
curl -v -X POST https://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "x"}' \
  2>&1 | tee .audit/evidence/CRIT-001-sqli-request.txt

# Capture tool output for specific finding
bandit -r ./src -t B608 -f json 2>&1 | tee .audit/evidence/HIGH-003-sqli-bandit.json

# Document code evidence
sed -n '40,50p' src/app.py | tee .audit/evidence/HIGH-003-code-snippet.txt

# Screenshot (if GUI available)
# Use browser developer tools → Network tab → copy as cURL
```

### 10.3 — Evidence File Naming

```
.audit/evidence/
  {SEVERITY}-{ID}-{type}.{ext}
  
Examples:
  CRIT-001-sqli-request.txt      # HTTP request/response
  CRIT-001-sqli-poc.py           # Proof of concept
  HIGH-003-code-snippet.txt      # Relevant code
  HIGH-003-bandit-output.json    # Tool finding
  MED-007-screenshot.png         # Visual evidence
```

### 10.4 — PoC Responsible Disclosure Standards

- PoC code must be **minimal** — demonstrate the issue without causing damage
- Never run PoC against production data — use synthetic/test data
- Mark all PoC files clearly: `# SECURITY RESEARCH ONLY — DO NOT DEPLOY`
- PoC for CRITICAL findings must be reviewed before sharing outside the team

---

## PHASE 11 — False Positive Triage

**Purpose:** SAST tools generate significant noise. Every finding must be manually verified before being reported. An unverified finding in a report destroys credibility.

### 11.1 — Triage Process (per finding)

For every tool finding, apply this 4-step verification:

**Step 1 — Read the finding in context**
```bash
# Open the flagged file at the flagged line number
sed -n "$((LINE-5)),$((LINE+10))p" <file>  # show 5 lines before/after
```

**Step 2 — Ask: Is this exploitable?**
- Can an external attacker reach this code path?
- Is the input controlled by the attacker (not internal/trusted)?
- Is there a downstream sink that processes the input unsafely?

**Step 3 — Classify the finding**

| Classification | Meaning | Action |
|---|---|---|
| `confirmed` | Verified exploitable, real vulnerability | Add to report with evidence |
| `false_positive` | Tool fired incorrectly — not exploitable | Mark FP, document reason |
| `informational` | Real pattern but no exploitable path in context | Log as INFO, no report entry |
| `out_of_scope` | Real issue but outside agreed scope | Log, note for separate review |

**Step 4 — Document your decision**
```json
{
  "tool_finding_id": "bandit-B608-001",
  "file": "src/app.py",
  "line": 42,
  "classification": "false_positive",
  "reason": "Input comes from internal trusted service via mTLS, not user-controlled",
  "reviewed_by": "Cesar Schneider",
  "reviewed_at": "2025-01-01T12:00:00Z"
}
```

### 11.2 — Common False Positive Patterns

| Tool | Common FP Pattern | How to verify it's a real issue |
|---|---|---|
| Bandit B608 | SQL query flagged but uses ORM | Check if raw f-string or ORM method |
| Semgrep XSS | `innerHTML` flagged but value is server-controlled constant | Trace data flow back to user input |
| Gitleaks | API key in test fixture file | Check if it's a real credential or placeholder |
| Checkov | Encryption flagged on dev/test resources | Confirm resource is not in production |
| Trivy | Base image CVE with no fix available | Check if CVE is exploitable in your context |
| pip-audit | CVE in transitive dep not directly imported | Check if vulnerable code path is reachable |

### 11.3 — FP Rate Tracking

Track false positive rate per tool — this informs future scans:
```
Tool          | Findings | Confirmed | FP  | FP Rate
Bandit        |    24    |    18     |  6  |  25%
Semgrep       |    41    |    28     | 13  |  32%
Trivy         |   120    |    15     | 105 |  88%  ← mostly base-image OS CVEs
Gitleaks      |     3    |     2     |  1  |  33%
```

---

## PHASE 12 — Retest & Verification

**Purpose:** A fix that isn't verified didn't happen. Every patched finding must be retested before the finding is marked `fixed` in the final report.

### 12.1 — Retest Protocol

For every finding marked as fixed:

**For SAST findings:**
```bash
# Re-run the specific rule on the fixed file
bandit -r <fixed_file> -t <test_id> -f json
semgrep --config=<rule> <fixed_file> --json

# Should return zero findings for this rule on this file
```

**For DAST findings:**
```bash
# Re-run the specific ZAP/Nuclei check against running app
nuclei -u $TARGET_URL -t <specific_template> -json

# Re-run the specific curl PoC — should now return safe response
curl -v <original_poc_request>
```

**For SCA/dependency findings:**
```bash
# Re-run pip-audit / npm audit after dependency update
pip-audit
npm audit
# Should show 0 known vulnerabilities for the updated package
```

**For IaC findings:**
```bash
# Re-run Checkov on the fixed config
checkov -f <fixed_terraform_file> --check <check_id>
```

### 12.2 — Retest Result Schema

```json
{
  "finding_id": "CRIT-001",
  "fix_applied": "Parameterized query in src/db.py line 42",
  "fix_commit": "abc1234",
  "retest_method": "bandit -r src/db.py -t B608",
  "retest_result": "PASS — zero findings",
  "retested_by": "Cesar Schneider",
  "retested_at": "2025-01-01T14:00:00Z",
  "final_status": "fixed"
}
```

### 12.3 — Closing Retest Report

After all fixes are applied and retested:
- Update all finding statuses in `.audit/findings-post-fix-YYYY-MM-DD.json`
- Recalculate risk score (should drop significantly)
- Document delta: *"Risk score reduced from 78 → 22 (72% reduction)"*
- Issue **Attestation Statement** if compliance requires it:

```
SECURITY RETEST ATTESTATION
Project: [name] | Date: YYYY-MM-DD
Original Risk Score: XX/100
Post-fix Risk Score: XX/100
Findings Fixed: N/Total
Remaining Open: N (documented in backlog)
Auditor: [name + signature]
```

---

## PHASE 13 — Scope & Exclusions

**Purpose:** Define explicitly what was tested AND what was not tested. Without this, any future incident can incorrectly blame the audit for missing something that was out of scope.

### 13.1 — Scope Definition Template

```markdown
## Audit Scope — [Project Name] — [Date]

### IN SCOPE
- Codebase: [repo URL, branch, commit SHA]
- Infrastructure: [AWS account ID, regions]
- Environments: [staging only / dev + staging / not production]
- Entry points tested: [list all APIs/URLs]
- Audit layers applied: [SAST, SCA, DAST, IaC, Cloud IAM, Supply Chain, Headers/TLS, IR Readiness]
- Compliance frameworks: [PCI-DSS, ISO 27001, SOC2, LGPD, none]

### EXPLICITLY OUT OF SCOPE
- Production database (no live data access)
- Third-party SaaS integrations (Stripe, Auth0, Twilio — governed by their security programs)
- [List any specific services/components excluded]
- Social engineering / phishing
- Physical security

### CONSTRAINTS
- Time-boxed: [N days]
- No destructive testing
- DAST run against staging only (not production)
- No exploit development beyond PoC demonstration

### ASSUMPTIONS
- Codebase provided is the current production version
- All credentials provided for testing are test-only accounts
- No SLAs impacted during testing

### AUTHORIZATION
- Authorized by: [name, title]
- Authorization date: [date]
- Emergency stop contact: [name, phone]
```

### 13.2 — Out-of-Scope Finding Handling

When you discover something clearly important that is out of scope:
- Document it in `.audit/out-of-scope-observations.md`
- Do NOT include in the risk score
- Mention in the report as: *"Observation outside agreed scope — recommend separate review"*
- Never exploit an out-of-scope component even if access is technically possible

---

## PHASE 14 — Git Workflow

`.audit/findings-post-fix-YYYY-MM-DD.json` — same schema, updated `status` field:
- `fixed` — patch applied and verified
- `partial_fix` — mitigation applied, architectural fix still needed
- `open` — not fixed yet, documented for backlog
- `accepted_risk` — known, intentional, documented

### 5.2 — Report structure

`.audit/report-YYYY-MM-DD.md`:

```markdown
# Security Audit Report — [Project Name]
**Date:** YYYY-MM-DD
**Auditor:** Cesar Schneider / B.IA
**Scope:** [what was audited]
**Risk Score:** XX/100 → [GREEN/YELLOW/ORANGE/RED]

## Executive Summary
[2-3 sentences: what was found, what risk level, key recommendation]

## Findings by Severity
### CRITICAL (N)
### HIGH (N)
### MEDIUM (N)
### LOW (N)

## Findings Fixed This Session (N/Total)

## Open Items — Backlog
[Table of open findings with recommended priority]

## Immediate Actions Required
[If RED/ORANGE: what must be fixed before next deploy]

## Compliance Notes
[Any findings that map to specific compliance requirements]
```

---

## PHASE 6 — Incident Response Readiness Assessment

**Purpose:** A breached system with good detection and response is survivable. A breached system with no visibility is a disaster. This phase assesses whether the app can detect, contain, and recover from an attack.

### 6.1 — Logging Coverage Audit

```bash
# Find logging configuration
find . -name "logging*" -o -name "log4*" -o -name "winston*" -o -name "logback*" 2>/dev/null | grep -v node_modules

# Check what's being logged (and what isn't)
grep -rn "logger\.\|logging\.\|console\.log\|print(" . --include="*.py" --include="*.js" --include="*.ts" | grep -iE "login|auth|error|exception|fail|access|deny" | grep -v node_modules | head -30

# Check for PII/secrets being logged (critical violation)
grep -rn "logger\.\|logging\." . --include="*.py" --include="*.js" | grep -iE "password|token|secret|credit_card|ssn|cpf" | grep -v node_modules
```

**Logging Checklist — What MUST be logged:**
- [ ] All authentication events (login success, login failure, logout, MFA)
- [ ] All authorization failures (403 responses, RBAC denials)
- [ ] All privilege escalation events (role changes, sudo, admin actions)
- [ ] All data access on sensitive resources (PII reads, bulk exports)
- [ ] All configuration changes (settings modified, user created/deleted)
- [ ] All input validation failures (potential attack probing)
- [ ] All external API calls (outbound data flows)
- [ ] SEV1/SEV2 error conditions with stack traces (server-side only)

**What must NEVER be logged:**
- [ ] Passwords (even hashed)
- [ ] Full credit card numbers (only last 4 digits)
- [ ] Session tokens or JWT contents
- [ ] API keys or secrets
- [ ] Full PII (mask email/phone in logs)

### 6.2 — Log Quality Assessment

Each log entry should have:
```json
{
  "timestamp": "2025-01-01T12:00:00.000Z",  // ISO8601, UTC
  "level": "WARN",
  "event_type": "AUTH_FAILURE",
  "user_id": "usr_abc123",                  // never email/name
  "ip_address": "1.2.3.4",
  "request_id": "req_xyz789",              // trace correlation
  "resource": "/api/admin/users",
  "action": "DELETE",
  "result": "DENIED",
  "reason": "insufficient_permissions"
}
```

Missing fields = blind spots for incident responders.

### 6.3 — Alerting & Detection Coverage

**Manual review — ask these questions:**
- Are failed login attempts alerted after N failures? (brute force detection)
- Is there an alert for logins from new geographies or devices?
- Are privilege escalation events alerted in real-time?
- Are anomalous data access volumes detected? (bulk export = exfiltration signal)
- Is there a SIEM collecting logs? (Splunk, Elastic, Datadog, AWS CloudWatch)
- What is the current Mean Time to Detect (MTTD)? Target: < 1 hour for CRITICAL

### 6.4 — Incident Response Checklist

- [ ] Incident response runbook exists and is current
- [ ] SEV1/SEV2 escalation path defined (who gets called at 3am?)
- [ ] Ability to revoke all sessions for a compromised account
- [ ] Ability to rotate secrets/credentials without downtime
- [ ] Ability to isolate a compromised service without full outage
- [ ] Forensic log retention: minimum 90 days hot, 1 year cold
- [ ] DR/BCP plan tested in the last 12 months
- [ ] Contact list for external notifications (users, regulators, partners)

### 6.5 — MTTD/MTTR Posture Rating

Score the application's detection/response maturity:

| Capability | Present | Score |
|---|---|---|
| Structured logging with correlation IDs | ✅/❌ | 0-20 |
| Real-time alerting on auth/authz events | ✅/❌ | 0-20 |
| SIEM integration | ✅/❌ | 0-20 |
| Documented IR runbook | ✅/❌ | 0-20 |
| Tested revocation/rotation capability | ✅/❌ | 0-20 |

**IR Readiness Score: X/100**
- 80-100: Production-ready
- 60-79: Acceptable with documented gaps
- 40-59: High risk — invest before next compliance audit
- 0-39: Critical gap — breach detection would be blind

Save to: `.audit/ir-readiness-YYYY-MM-DD.md`

---

## PHASE 7 — DevSecOps Pipeline Review

**Purpose:** Security embedded in the SDLC catches vulnerabilities before they reach production. This phase audits whether the development pipeline itself is secure and whether security gates exist at each stage.

### 7.1 — Pipeline Security Gates Audit

```bash
# Find all CI/CD pipeline configs
find . -name "*.yml" -path "*/.github/workflows/*" \
     -o -name ".gitlab-ci.yml" \
     -o -name "Jenkinsfile" \
     -o -name ".circleci/config.yml" \
     -o -name "azure-pipelines.yml" 2>/dev/null

# Check what security tools run in CI
grep -rn "bandit\|semgrep\|snyk\|trivy\|gitleaks\|checkov\|sonarqube\|zap" .github/workflows/ .gitlab-ci.yml 2>/dev/null
```

**DevSecOps Maturity Checklist:**

**Commit Stage (every push):**
- [ ] Pre-commit hooks: secret scanning (gitleaks/detect-secrets) blocks commits with secrets
- [ ] Pre-commit hooks: linting + basic SAST
- [ ] Signed commits enforced on protected branches

**Build Stage (every PR):**
- [ ] SAST runs on every PR (Bandit/Semgrep/SonarQube)
- [ ] SCA runs on every PR (Snyk/Dependabot/pip-audit)
- [ ] Secret scanning runs on every PR
- [ ] Build fails on CRITICAL/HIGH findings (not just reports)
- [ ] PR requires 2 reviewers minimum for sensitive code paths
- [ ] Branch protection: no force push, no direct push to main

**Test Stage:**
- [ ] DAST runs against ephemeral test environment on every PR
- [ ] Container image scanned before being pushed to registry
- [ ] IaC scanned (Checkov/tfsec) before plan/apply

**Deploy Stage:**
- [ ] Artifacts signed before deployment
- [ ] Deployment requires approval for production
- [ ] Secrets injected at runtime (never baked into image)
- [ ] Rollback capability verified

**Post-Deploy:**
- [ ] Automated compliance checks run post-deploy
- [ ] Anomaly detection alerts active within 5 minutes of deploy
- [ ] DRBM (dark-reading baseline) — compare pre/post deploy security posture

### 7.2 — Dependency Automation

- [ ] Dependabot or Renovate enabled and active
- [ ] Auto-merge enabled for patch-level dependency updates
- [ ] Security advisories trigger immediate PR creation
- [ ] License compliance checked on new dependencies

### 7.3 — Developer Security Training Signal

Look for evidence of security culture:
```bash
# Any security-focused documentation?
find . -name "SECURITY.md" -o -name "security.md" -o -name "THREAT_MODEL.md" 2>/dev/null

# Responsible disclosure / bug bounty policy?
cat SECURITY.md 2>/dev/null | head -30
```

- [ ] `SECURITY.md` exists with responsible disclosure contact
- [ ] Bug bounty program documented (if applicable)
- [ ] Security review checklist in PR template

Save to: `.audit/devsecops-review-YYYY-MM-DD.md`

---

## PHASE 8 — Cloud IAM Deep Dive

```bash
git checkout -b security/audit-fixes-YYYY-MM-DD

# Commit each fix separately
git add <fixed_file>
git commit -m "fix(security): CWE-89 parameterized queries in src/db.py"

# After all fixes
git push origin security/audit-fixes-YYYY-MM-DD
```

One commit per finding fixed. Commit message must reference CWE and file.

---

## Pitfalls

- **Never skip Phase 0.** Running tools without context generates hundreds of false positives and misses the real risks.
- **Auth + IDOR are always paired.** You can't fix IDOR without first having an identity model. Fix auth architecture first.
- **Secret scanning must check git history**, not just the current tree. Secrets deleted from files still live in git history.
- **IaC misconfigurations are often more critical than code bugs.** A public S3 bucket or open security group exposes everything.
- **SAST tools have high false-positive rates.** Always manually verify before marking a finding as real.
- **Container base image CVEs.** Most CVEs in Trivy output are in the OS layer of the base image. Prioritize app-layer CVEs first.
- **`alg: none` JWT attacks.** Always verify the JWT library forces algorithm validation, especially with HS256 + weak secrets.
- **`.env` files in git history.** Even if .gitignore was added later, the file may be in history. Run `gitleaks detect` on full history.
- **Verbose error responses.** Stack traces returned to users are goldmines for attackers. Always check error handlers.
- **Rate limiting is often missing on auth endpoints.** Brute-force on `/login`, `/reset-password`, `/verify-otp` is trivially exploitable.
- **Risk score cap at 100.** Normalize — don't let the score exceed 100.
- **Compliance ≠ Security.** PCI-DSS / ISO 27001 compliance does not mean the app is secure. Flag both separately.

---

## Environment Bootstrap

### Install all tools at once (Ubuntu/Debian)

```bash
sudo apt-get update -y && sudo apt-get install -y python3-pip nodejs npm curl

# Python tools
pip3 install bandit semgrep njsscan pip-audit detect-secrets checkov cyclonedx-bom

# Node tools
npm install -g @stoplight/spectral-cli @cyclonedx/cyclonedx-npm

# Trivy (container scanner)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ~/.local/bin

# Gitleaks (git history secret scanner)
wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz -O /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C ~/.local/bin gitleaks

export PATH=$PATH:~/.local/bin
```

### Verify
```bash
bandit --version && semgrep --version && checkov --version && trivy --version && gitleaks version
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `bandit`/`semgrep` not found | `export PATH=$PATH:~/.local/bin` |
| `semgrep` very slow | Create `.semgrepignore` excluding `node_modules`, `.venv`, `dist` |
| `trivy` SSL error | `trivy --insecure image ...` or configure proxy |
| `gitleaks` finds nothing | Run with `--verbose` to confirm it's scanning history |
| `checkov` skips Terraform | Run with `--framework terraform` explicitly |
| `detect-secrets` too many FPs | Tune with `--exclude-files` and `--exclude-secrets` |
| `npm audit` fails | Run `npm install` first to generate `package-lock.json` |

---

## Related Skills

- `web-app-auth` — JWT/session auth implementation (fixes CWE-287, CWE-306, CWE-639)
- `social-media-video` — content pipeline (unrelated — skip)
