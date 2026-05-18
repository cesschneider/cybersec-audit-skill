#!/usr/bin/env python3
"""
check_findings.py — CI gate for security findings.

Reads .audit/semgrep-ci.json and .audit/bandit-ci.json and fails the build
if any CRITICAL severity findings are present.

Exit codes:
  0 — no critical findings (or no scan output available)
  1 — one or more critical findings detected
"""

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

def main():
    all_findings = []
    all_findings += check_semgrep(load_json(f"{AUDIT_DIR}/semgrep-ci.json"))
    all_findings += check_bandit(load_json(f"{AUDIT_DIR}/bandit-ci.json"))
    all_findings += check_entropy(load_json(f"{AUDIT_DIR}/entropy-ci.json"))

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
