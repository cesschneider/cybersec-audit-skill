# Security Policy

## Supported Versions

Only the latest released version of this project receives security fixes.
Older tags are provided for reference only and will not be patched.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
to submit a report directly to the maintainers. Navigate to the Security tab of
this repository and click "Report a vulnerability".

We aim to acknowledge all reports within **72 hours** and will keep you informed
as we investigate and address the issue. We ask that you allow us a reasonable
remediation window before any public disclosure.

## Scope

### What IS a security issue

The following are in scope for vulnerability reports:

- The **skill tooling** itself: prompt injection vectors in the Claude AI skill
  definition, insecure handling of tool outputs, or logic that could cause the
  skill to exfiltrate data or execute unintended commands.
- **CI scripts and GitHub Actions workflows**: supply-chain risks, use of
  unpinned third-party actions, secrets exposed in logs, or workflow permissions
  that could be abused via pull-request attacks.
- **Repository infrastructure**: branch protection misconfigurations, insecure
  default settings, or anything that could allow unauthorized code to be merged
  or published.
- **The findings schema or report template** if they could cause downstream
  consumers to execute arbitrary code (e.g., template injection leading to RCE
  in a rendering engine).

### What is NOT a security issue

> **This repository ships intentionally vulnerable demo applications.**

The following are **expected, intentional, and out of scope**:

- Any vulnerability found inside `demo-apps/flask-app/`, `demo-apps/node-app/`,
  `demo-apps/go-app/`, or `demo-apps/react-app/`. These apps contain deliberate
  flaws (SQL injection, XSS, command injection, SSRF, insecure deserialization,
  hardcoded secrets, etc.) that exist solely to provide realistic audit targets
  for skill validation. Reporting them wastes your time and ours.
- Missing security headers, exposed debug endpoints, or weak authentication in
  the demo apps — again, intentional.
- CVEs in demo-app dependencies that are there on purpose to exercise the
  dependency-scanning layer of the audit pipeline.

## Out of Scope

The following are also out of scope regardless of where they appear:

- Vulnerabilities in third-party tools invoked by the skill (Semgrep, Bandit,
  gosec, ESLint, etc.) — report those to the respective upstream projects.
- Social engineering attacks targeting maintainers.
- Physical security issues.
- Denial-of-service attacks against GitHub infrastructure.
- Issues that require physical access to a maintainer's machine.

Thank you for helping keep this project and its users safe.
