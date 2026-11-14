#!/usr/bin/env python3
"""
check_findings.py — CI gate for security findings.

Reads .audit/semgrep-ci.json and .audit/bandit-ci.json and fails the build
if any CRITICAL severity findings are present.

Modes:
  default            gate mode — fail if any CRITICAL/HIGH finding exists
                     (use on real application code).
  --expect-findings  detection-regression mode — fail if NO critical/high
                     finding exists. Use on the intentionally vulnerable
                     demo apps: it proves the scanners still detect the
                     planted vulnerabilities (and catches a scanner that
                     silently failed to run).

Exit codes:
  0 — gate passed
  1 — gate failed
"""

import argparse
import json
import sys
import os

CRITICAL_SEVERITIES = {"critical", "error", "ERROR", "CRITICAL"}
AUDIT_DIR = ".audit"

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None

def check_semgrep(data):
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        severity = result.get("extra", {}).get("severity", "").upper()
        if severity == "ERROR":
            findings.append({
                "tool": "semgrep",
                "severity": severity,
                "file": result.get("path", "?"),
                "line": result.get("start", {}).get("line", "?"),
                "message": result.get("extra", {}).get("message", "")[:120],
            })
    return findings

def check_bandit(data):
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        severity = result.get("issue_severity", "").upper()
        if severity == "HIGH":
            findings.append({
                "tool": "bandit",
                "severity": severity,
                "file": result.get("filename", "?"),
                "line": result.get("line_number", "?"),
                "message": result.get("issue_text", "")[:120],
            })
    return findings

def check_entropy(data):
    if not data:
        return []
    findings = []
    for result in (data if isinstance(data, list) else []):
        if result.get("severity", "").upper() in CRITICAL_SEVERITIES:
            findings.append({
                "tool": "entropy_scan",
                "severity": result.get("severity", "?").upper(),
                "file": result.get("file", "?"),
                "line": result.get("line", "?"),
                "message": result.get("description", "")[:120],
            })
    return findings

def main(argv=None):
    ap = argparse.ArgumentParser(description="CI gate for security findings")
    ap.add_argument("--expect-findings", action="store_true",
                    help="detection-regression mode for intentionally vulnerable demo code")
    ap.add_argument("--min", type=int, default=1,
                    help="minimum critical/high findings expected with --expect-findings")
    args = ap.parse_args(argv)

    all_findings = []
    all_findings += check_semgrep(load_json(f"{AUDIT_DIR}/semgrep-ci.json"))
    all_findings += check_bandit(load_json(f"{AUDIT_DIR}/bandit-ci.json"))
    all_findings += check_entropy(load_json(f"{AUDIT_DIR}/entropy-ci.json"))

    if args.expect_findings:
        by_tool = {}
        for f in all_findings:
            by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1
        if len(all_findings) >= args.min:
            print(f"✅ Detection regression passed: {len(all_findings)} critical/high finding(s) "
                  f"detected in intentionally vulnerable code {by_tool}.")
            return 0
        print(f"❌ Detection regression FAILED: expected at least {args.min} critical/high finding(s) "
              f"in intentionally vulnerable code, got {len(all_findings)}. "
              "A scanner may have failed to run or lost a rule.")
        return 1

    if not all_findings:
        print("✅ CI gate: no critical/high findings detected.")
        return 0

    print(f"\n❌ CI gate FAILED — {len(all_findings)} critical/high finding(s):\n")
    for f in all_findings:
        print(f"  [{f['tool']}] {f['severity']} @ {f['file']}:{f['line']}")
        print(f"    {f['message']}")
        print()

    print("Fix these findings before merging. See .audit/ for full reports.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
