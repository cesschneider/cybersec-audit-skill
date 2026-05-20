# Changelog — Cybersecurity Audit Skill

All notable changes to this skill are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.1.0] — 2025-05-19

### Added
- **Phase 0.5 — Tool Currency Check** — mandatory pre-audit gate that ensures all
  scanner definitions (Semgrep rules, Nuclei templates, Trivy NVD DB, Checkov rules)
  are updated to the latest available version before any scan runs.
- **NVD API integration in Phase 0.5** — queries the National Vulnerability Database
  for CRITICAL CVEs published in the last 7 days, filtered by the target stack's
  technology keywords.
- **OWASP version currency check** — automated GitHub API queries to detect when
  new OWASP Top 10 (Web) or OWASP API Security editions are published, so the skill
  can be updated promptly.
- **Currency snapshot output** — `.audit/currency/tool-versions-YYYY-MM-DD.txt`
  captures exact tool versions and OWASP reference editions used for each audit,
  creating a reproducible audit trail.
- **Version header in SKILL.md** — skill version, OWASP reference editions, and
  last-updated date now displayed at the top of the skill for immediate visibility.
- **`references/competitive-comparison.md`** — full competitive analysis table
  comparing this skill against Fortify, Checkmarx, Veracode, Snyk, and SonarQube
  across 28 capability dimensions. Includes pricing, unique differentiators, and
  when-to-use decision matrix.
- **`references/CHANGELOG.md`** — this file. Tracks all skill changes over time.

### Changed
- SKILL.md now opens with a version/currency banner before the Philosophy section.
- Phase 0.5 inserted between Phase 0 (Context Gathering) and Phase 1 (Threat Modeling)
  to enforce tool freshness as a hard gate.

### Rationale
> *"How do you guarantee this skill covers the most recent CVEs and OWASP best practices?"*
>
> The skill workflow is intentionally methodology-based (STRIDE, OWASP frameworks) so
> it doesn't become stale when individual CVEs are published. However, the scanners
> it orchestrates (Semgrep, Nuclei, Trivy) pull live definitions — Phase 0.5 makes
> this update step explicit and auditable rather than assumed.

---

## [2.0.0] — 2025-05-18

### Added (14 new phases — CISO-grade gap fill)
- **Phase 1 — Threat Modeling** — STRIDE, PASTA, Attack Trees. Mandatory before any tool runs.
- **Layer 8 — DAST** — OWASP ZAP (baseline + full + API), Nuclei, Nikto. Tests the running application.
- **Layer 10 — Supply Chain Security** — SBOM (CycloneDX), OSV Scanner, Sigstore/cosign,
  git commit signing verification, CI/CD pipeline security review, dependency confusion detection.
- **Layer 11 — Security Headers & TLS** — testssl.sh, sslyze, curl-based header audit,
  automated grade check via securityheaders.com and SSL Labs.
- **Phase 6 — Incident Response Readiness** — logging coverage audit, alerting gaps,
  MTTD/MTTR scoring (0–100), IR runbook review.
- **Phase 7 — DevSecOps Pipeline Review** — CI/CD security gates at commit/build/test/deploy/post-deploy,
  Dependabot/Renovate, developer security culture signals.
- **Phase 8 — Cloud IAM Deep Dive** — Prowler, ScoutSuite (AWS/GCP/Azure), stale credential
  detection, wildcard policy finder, 6 known privilege escalation paths.
- **Phase 9 — Mobile & Frontend Security** — MobSF for APK/IPA, React SPA patterns
  (dangerouslySetInnerHTML, localStorage, CSP), certificate pinning checklist.
- **Phase 10 — Evidence Collection** — per-severity evidence standards, PoC responsible
  disclosure rules, structured file naming convention.
- **Phase 11 — False Positive Triage** — 4-step verification process, classification schema
  (confirmed / false_positive / informational / out_of_scope), FP rate tracking per tool.
- **Phase 12 — Retest & Verification** — per-finding retest protocol for SAST/DAST/SCA/IaC,
  retest result schema, post-fix attestation statement.
- **Phase 13 — Scope & Exclusions** — formal scope definition template, authorization requirements,
  out-of-scope finding handling protocol.
- **Remediation Roadmap (30/60/90-day)** — effort estimates, owner assignment, business risk
  language, accepted risk sign-off template.
- **Risk Score Model** — 0–100 numeric score with CRITICAL=25/HIGH=10/MEDIUM=3/LOW=1 weights,
  mapped to RED/ORANGE/YELLOW/GREEN traffic light.
- **IR Readiness Score** — separate 0–100 score measuring detection and response posture.
- **`references/ciso-partnership-approach.md`** — CISO sales approach playbook:
  ICP profile, 6-slide deck structure, 5-stage outreach sequence, objection handling.
- **Skill Gap Analysis section** — reusable pattern for auditing any skill against an
  expert-level benchmark.
- **Environment Bootstrap** — one-command install script for all tools on Ubuntu/Debian.
- **Troubleshooting table** — common tool failures and fixes.

### Changed
- Skill description updated to reflect full-spectrum coverage.
- SAST section expanded with React/frontend and additional language configs.
- Auth & AuthZ deep dive expanded with full checklist.
- Report template upgraded with Executive Summary, Risk Score Breakdown, Top 5 Findings
  executive view, Compliance Mapping, and IR Readiness Score.

### Rationale
Gap analysis against CISO/Head of Security expert profile (20+ years experience).
14 gaps identified and filled to reach production-grade quality.

---

## [1.0.0] — 2025-05-01 (initial release)

### Added
- Phase 0 — Context Gathering (8 mandatory questions + 5 conditional)
- Phase 2 — Tooling Setup (install commands for all base tools)
- Layer 1 — SAST (Bandit, Semgrep, njsscan — Python, Node, Go, Java)
- Layer 2 — SCA (pip-audit, npm audit, CycloneDX SBOM)
- Layer 3 — Secret Scanning (detect-secrets, gitleaks + git history)
- Layer 4 — IaC Security (Checkov — Terraform, K8s, Docker)
- Layer 5 — Container Security (Trivy)
- Layer 6 — API Security (OWASP API Top 10 manual checklist, Spectral)
- Layer 7 — Auth & AuthZ deep dive (JWT, RBAC, IDOR checklists)
- Phase 3 — Triage & Classification (finding schema, risk score)
- Phase 4 — Autofix Pass (12 CWE-mapped fix patterns)
- Phase 14 — Git Workflow (one commit per finding, branch naming)
- Pitfalls section (12 common mistakes)
- Basic report template

---

## Planned Improvements (Backlog)

| Priority | Improvement | Rationale |
|---|---|---|
| 🔴 High | **Weekly cron job** — monitors NVD + OWASP GitHub releases and sends Telegram alert when skill needs updating | Keeps skill currency automated, not manual |
| 🔴 High | **LLM-powered CVE relevance filter** — after NVD query, use Claude to determine which new CVEs are relevant to the audit target's stack before reporting | Reduces noise from irrelevant CVEs |
| 🟠 Medium | **OWASP Top 10 2025 update** — incorporate new edition when published | Keep OWASP alignment current |
| 🟠 Medium | **MITRE ATT&CK integration in Phase 1** — map STRIDE findings to ATT&CK TTPs for threat intelligence enrichment | Elevates threat model quality |
| 🟠 Medium | **GraphQL security layer** — dedicated checklist for GraphQL APIs (introspection, batching attacks, authorization bypass) | Increasingly common API style |
| 🟡 Low | **Portuguese (PT-BR) version** — translate skill for Brazilian market (key for LGPD compliance audits) | Eworks Labs primary market |
| 🟡 Low | **Kubernetes runtime security** — Falco, OPA Gatekeeper, network policy audit | Cloud-native hardening depth |
| 🟡 Low | **AI/LLM security layer** — OWASP LLM Top 10 (prompt injection, model inversion, training data poisoning) | Emerging attack surface for AI-powered apps |

---

*Maintained by Eworks Labs / B.IA*
*GitHub: [cesschneider/cybersec-audit-skill](https://github.com/cesschneider/cybersec-audit-skill)*
