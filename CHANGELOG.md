# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-05-19

Initial public release of the cybersecurity audit Claude AI skill.

### Added

- **3-layer audit pipeline**: static analysis (SAST), dependency vulnerability scanning,
  and architecture/design review (ARCH) layers executed in sequence by the skill.
- **SAST integration**: automated invocation of Semgrep and Bandit for Python targets,
  ESLint security plugins for JavaScript/TypeScript, and gosec for Go targets.
- **Dependency scanning**: npm audit, pip-audit, and Go module vulnerability checks
  wired into the audit workflow.
- **Architecture findings (ARCH) support**: skill can surface design-level and
  infrastructure security issues beyond line-level SAST hits.
- **Findings schema**: structured JSON schema for audit findings including `risk_label`,
  `score_breakdown`, `post_fix_delta`, severity, CWE mapping, file/line references,
  and remediation guidance.
- **Report template**: Markdown report template that renders the findings schema into
  a human-readable audit report with executive summary, per-finding detail sections,
  and a remediation scorecard.
- **Vulnerable demo applications** (intentionally insecure, for skill validation):
  - `demo-apps/flask-app/` — Python Flask app with SQL injection, IDOR, insecure
    deserialization, and hardcoded secrets.
  - `demo-apps/node-app/` — Node.js/Express app with XSS, prototype pollution,
    path traversal, and missing security headers.
  - `demo-apps/go-app/` — Go HTTP service with command injection, SSRF, and
    improper error handling.
  - `demo-apps/react-app/` — React SPA with dangerouslySetInnerHTML XSS vectors
    and exposed sensitive data in client bundles.
- **CI workflow** (`.github/workflows/audit.yml`): GitHub Actions workflow that runs
  the full audit pipeline against the demo apps on every push and pull request,
  uploads the generated report as a build artifact, and fails the build on
  findings above a configurable severity threshold.
- **Skill definition**: Claude AI skill manifest and prompt instructions enabling
  Claude Code / Hermes to invoke the audit pipeline as a first-class skill command.
- **Claude Code (Hermes) setup instructions** in README: step-by-step guide to
  installing and registering the skill under the Hermes CLI distribution.
- **Claude Code (Anthropic CLI) setup instructions** in README: parallel setup
  guide for users running the official Anthropic Claude Code CLI.
- **CONTRIBUTING.md**: contributor guidelines covering branching strategy, commit
  conventions, how to add new demo-app vulnerabilities, and how to extend the
  findings schema.
- **Hardened `.gitignore`**: excludes `.audit/` output directories, tool caches,
  secrets files, IDE metadata, and OS artifacts to prevent accidental leakage of
  audit results or credentials.
- MIT License (copyright 2025 Cesar Schneider).

### Notes

- Demo app vulnerabilities are **intentional**. They exist solely to provide a
  realistic target for skill validation. Do not report them as security issues
  (see SECURITY.md for scope).
- Audit output artifacts (`.audit/`) are excluded from the repository via
  `.gitignore`; only the report template and schema are versioned.

[Unreleased]: https://github.com/cesarschneider/cybersec-audit-skill/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cesarschneider/cybersec-audit-skill/releases/tag/v1.0.0
