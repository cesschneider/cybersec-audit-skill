# Competitive Comparison — Cybersecurity Audit Skill vs. Enterprise Tools

> **Scope:** This document compares the Cybersecurity Audit Skill (powered by B.IA / Eworks Labs)
> against the leading commercial SAST/DAST/SCA platforms. Use this as a sales reference,
> technical briefing, or CISO partnership conversation starter.

---

## 1 — Feature Coverage Matrix

| Capability | **Skill + B.IA** | Fortify (OpenText) | Checkmarx One | Veracode | Snyk | SonarQube (Cloud) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **SAST** | ✅ Multi-stack (Semgrep + Bandit + njsscan) | ✅ Best-in-class (Java/.NET) | ✅ Strong | ✅ Strong | ⚠️ Limited | ✅ Strong |
| **DAST (running app)** | ✅ ZAP + Nuclei + Nikto | ❌ Separate product (WebInspect) | ❌ Separate product | ✅ Yes | ❌ No | ❌ No |
| **SCA (dependencies)** | ✅ pip-audit + npm audit + OSV | ⚠️ Addon | ✅ Yes | ✅ Yes | ✅ Best-in-class | ✅ Yes |
| **Secret Scanning** | ✅ Gitleaks (full git history) + detect-secrets | ⚠️ Limited | ✅ Yes | ⚠️ Limited | ✅ Yes | ✅ Yes |
| **IaC Security** | ✅ Checkov (Terraform, K8s, Docker, Helm) | ❌ No | ✅ KICS | ❌ No | ✅ Snyk IaC | ❌ No |
| **Container / Image Scanning** | ✅ Trivy | ❌ No | ⚠️ Limited | ❌ No | ✅ Yes | ❌ No |
| **Cloud IAM Deep Dive** | ✅ Prowler + ScoutSuite (AWS/GCP/Azure) | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **API Security (OWASP API Top 10)** | ✅ Manual review + Spectral | ❌ No | ⚠️ Partial | ⚠️ Partial | ❌ No | ❌ No |
| **Threat Modeling (STRIDE/PASTA/Attack Trees)** | ✅ Full — mandatory before any scan | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **Mobile Security (MobSF / iOS / Android)** | ✅ MobSF + cert pinning + deep link review | ❌ No | ❌ No | ✅ Mobile product | ❌ No | ❌ No |
| **Frontend / SPA Security (React)** | ✅ Semgrep React + CSP + SRI | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial |
| **Supply Chain Security (SBOM + Sigstore)** | ✅ CycloneDX SBOM + OSV + commit signing | ❌ No | ⚠️ Partial | ❌ No | ⚠️ Partial | ❌ No |
| **Security Headers & TLS** | ✅ testssl.sh + sslyze + curl headers | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **Incident Response Readiness (IR score)** | ✅ Logging + alerting + MTTD/MTTR scoring | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **DevSecOps Pipeline Review** | ✅ CI/CD gates audit + developer security culture | ❌ No | ⚠️ Integration docs only | ❌ No | ✅ Integrations | ❌ No |
| **Autofix Patches (code-level)** | ✅ CWE-mapped fix patterns with code examples | ❌ No | ⚠️ Suggestions only | ⚠️ Suggestions only | ✅ Auto-PRs (SCA) | ⚠️ Suggestions only |
| **False Positive Triage Process** | ✅ 4-step verification + FP rate tracking | ❌ No guidance | ❌ No guidance | ❌ No guidance | ❌ No guidance | ❌ No guidance |
| **Retest & Verification Protocol** | ✅ Per-finding retest + attestation statement | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **Evidence Collection (PoC, naming standard)** | ✅ Structured evidence per severity level | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **Scope & Exclusions Documentation** | ✅ Formal authorization + out-of-scope handling | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **30/60/90-Day Remediation Roadmap** | ✅ With effort estimates + business risk language | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **Executive Risk Score (0–100)** | ✅ RED/ORANGE/YELLOW/GREEN with scoring model | ❌ No | ⚠️ CVSS only | ⚠️ CVSS only | ⚠️ CVSS only | ⚠️ CVSS only |
| **Business Context in Report** | ✅ Language for board / CFO / CTO | ❌ Technical only | ❌ Technical only | ❌ Technical only | ❌ Technical only | ❌ Technical only |
| **Compliance Mapping (PCI, SOC2, ISO, LGPD)** | ✅ Findings mapped to framework controls | ⚠️ Limited | ✅ Yes | ✅ Yes | ⚠️ Limited | ⚠️ Limited |
| **Context-First Methodology (Phase 0)** | ✅ Mandatory context gathering before any scan | ❌ Scans immediately | ❌ Scans immediately | ❌ Scans immediately | ❌ Scans immediately | ❌ Scans immediately |
| **Tooling Cost** | ✅ **$0 — 100% open source** | ❌ $20k–$80k/yr | ❌ $30k–$100k/yr | ❌ $15k–$60k/yr | ⚠️ $0–$25k/yr | ⚠️ $0–$30k/yr |
| **Time to First Scan** | ✅ Minutes (bootstrap script) | ❌ Days of setup | ❌ Days of setup | ❌ Hours | ✅ Minutes | ⚠️ Hours |
| **Requires Vendor Contract / Lock-in** | ✅ **No** | ❌ Yes | ❌ Yes | ❌ Yes | ❌ Yes | ❌ Yes |

---

## 2 — Depth Comparison by Tool Category

### 2.1 — SAST Depth

| Dimension | **Skill + B.IA** | Fortify | Checkmarx | Veracode | Snyk Code |
|---|---|---|---|---|---|
| Languages supported | Python, JS/TS, Go, Java, React | Java, .NET, C/C++ (best) | 30+ languages | 30+ languages | 20+ languages |
| Custom rule authoring | ✅ Semgrep YAML rules | ✅ (complex) | ✅ (complex) | ❌ No | ❌ No |
| OWASP Top 10 coverage | ✅ Explicit per category | ✅ | ✅ | ✅ | ⚠️ Partial |
| Business logic flaws | ✅ Manual review phase | ❌ | ❌ | ❌ | ❌ |
| Context-aware FP reduction | ✅ Manual 4-step triage | ❌ Auto-suppress only | ⚠️ AI-assisted | ❌ Auto-suppress | ⚠️ AI-assisted |

### 2.2 — Reporting Depth

| Report Element | **Skill + B.IA** | Enterprise Tools (avg) |
|---|---|---|
| Executive summary | ✅ In business language | ⚠️ Technical summary |
| Risk score | ✅ 0–100 with business context | ⚠️ CVSS 0–10 only |
| Remediation roadmap | ✅ 30/60/90 days, effort, owner | ❌ Not included |
| Compliance mapping | ✅ PCI / SOC2 / ISO / LGPD / GDPR | ⚠️ Varies by product tier |
| Accepted risk documentation | ✅ Formal risk owner sign-off template | ❌ |
| Attestation statement | ✅ Post-retest formal attestation | ❌ |
| Evidence package | ✅ PoC + request/response + code snippets | ❌ Screenshots only |

---

## 3 — Unique Differentiators (What No Commercial Tool Does)

These capabilities exist **only** in the Cybersecurity Audit Skill. No commercial tool — at any price point — replicates this combination:

### 🧠 1. Threat Modeling as a Pre-Scan Mandatory Gate
> "A security audit without a threat model is just a checklist."

Every commercial tool scans first and asks questions never. The skill enforces STRIDE, PASTA, and attack trees **before** a single tool runs. This means the audit focuses on real risk paths — not a dump of 500 CVEs in OS packages nobody can exploit.

**Result:** Findings are contextualized to the actual business risk, not the theoretical CVSS score.

---

### 💼 2. Business-Language Report (Board-Ready)
Commercial tools produce technical findings lists. CISOs then spend days translating for the board. The skill produces:
- Executive summary in plain language
- Risk score with a color-coded 0–100 scale
- Roadmap a CFO can read in 5 minutes
- Business impact per finding (not just CWE reference)

**Result:** The audit report goes directly from the auditor to the board — no translation layer needed.

---

### 🔄 3. Full Audit Lifecycle in One Workflow
| Stage | Commercial tools | Skill + B.IA |
|---|---|---|
| Context gathering | ❌ None | ✅ Phase 0 |
| Threat modeling | ❌ Separate engagement | ✅ Phase 1 |
| Multi-layer scanning | ⚠️ Multiple products | ✅ Single workflow |
| FP triage | ❌ Manual, no guidance | ✅ 4-step process |
| Autofix | ⚠️ Suggestions only | ✅ Code-level patches |
| Retest | ❌ Manual | ✅ Structured protocol |
| Evidence packaging | ❌ Screenshots | ✅ PoC + request/response |
| Attestation | ❌ None | ✅ Formal statement |

---

### 🔍 4. IR Readiness Score
No commercial SAST/DAST/SCA tool tells you whether your app can **detect** an attack in production. The skill measures:
- Logging coverage (what's logged, what's missing, what must never be logged)
- Alerting effectiveness (brute force detection, geo-anomaly, privilege escalation)
- MTTD/MTTR posture rated 0–100
- Incident response runbook review

**Result:** A 0-vulnerability app with no logging is more dangerous than an app with 3 HIGH findings and a SIEM. Only this skill captures that.

---

### ☁️ 5. Cloud IAM Privilege Escalation Analysis
Tools like Checkmarx and Snyk scan your IaC files for misconfigurations. None of them analyze **live cloud IAM** for privilege escalation paths — the #1 cause of cloud breaches. The skill uses Prowler + ScoutSuite to detect:
- Stale credentials (>90 days inactive)
- Wildcard `*` policies
- Cross-account trust relationships
- 6 known privilege escalation paths (PassRole, CreatePolicyVersion, etc.)

---

## 4 — Pricing & ROI Comparison

| | **Skill + B.IA** | Fortify | Checkmarx | Veracode | Snyk Business |
|---|---|---|---|---|---|
| **Annual tooling cost** | **$0** | $20k–$80k | $30k–$100k | $15k–$60k | $10k–$25k |
| **Setup time** | Minutes | Days–weeks | Days | Hours | Hours |
| **Threat modeling** | Included | Not included | Not included | Not included | Not included |
| **IR Readiness** | Included | Not included | Not included | Not included | Not included |
| **Business-ready report** | Included | Not included | Not included | Not included | Not included |
| **Vendor lock-in** | None | High | High | High | Medium |
| **Coverage layers** | 14 phases | 2–3 products | 3–4 products | 3–4 products | 2–3 products |

> **Key insight:** A company that buys Fortify (SAST) + WebInspect (DAST) + Fortify SCA spends $60k–$150k/year and still doesn't get threat modeling, IR readiness, or a board-ready report. The skill covers all of that with $0 in tooling.

---

## 5 — When to Use Which

| Scenario | Best Choice | Why |
|---|---|---|
| Enterprise with 500+ devs, Java/.NET monolith | Fortify + this skill | Fortify's Java depth + skill's threat modeling + reporting layer |
| Startup, multi-stack, tight budget | **Skill + B.IA only** | Full coverage, zero tooling cost, fast time-to-value |
| Pre-fundraising security audit | **Skill + B.IA only** | Board-ready report, risk score, roadmap — exactly what investors ask for |
| CISO needing board presentation | **Skill + B.IA only** | Business language, 30/60/90-day roadmap, accepted risk documentation |
| SCA-heavy (many npm/pip dependencies) | Snyk + this skill | Snyk's auto-PRs for SCA + skill for full-spectrum coverage |
| Regulated industry (PCI, HIPAA, LGPD) | **Skill + B.IA + compliance layer** | Findings mapped to framework controls, attestation statement |
| Cloud-native, K8s, multi-cloud | **Skill + B.IA only** | IaC + Container + Cloud IAM in one workflow |
| Mobile app + API + web (full stack) | **Skill + B.IA only** | Only option covering all three in one audit |

---

## 6 — Legend

| Symbol | Meaning |
|---|---|
| ✅ | Fully supported — native capability |
| ⚠️ | Partial — limited coverage, requires addon, or manual effort |
| ❌ | Not supported — requires separate product or engagement |

---

*Generated by B.IA / Eworks Labs — Cybersecurity Audit Skill v2.0*
*Reference file: `references/competitive-comparison.md`*
*Companion skill: `security/cybersecurity-audit/SKILL.md`*
