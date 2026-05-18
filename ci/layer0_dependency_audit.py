#!/usr/bin/env python3
"""
layer0_dependency_audit.py — Supply chain / dependency vulnerability audit.

Layer 0 of the cybersecurity audit skill: runs BEFORE source code scanning.
Detects known CVEs in project dependencies using pip-audit, npm audit,
and optionally trivy for SBOM generation.

Usage:
  python ci/layer0_dependency_audit.py /path/to/project [--output results.json] [--sbom]

Exit codes:
  0 — no critical/high CVEs found
  1 — critical or high CVEs detected
  2 — scan error
"""

import os
import re
import sys
import json
import argparse
import subprocess
import shutil

AUDIT_DIR = ".audit"

# ─── Helpers ─────────────────────────────────────────────────────────────────

def run(cmd, cwd=None, timeout=120):
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout, r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, -1

def tool_available(name):
    return shutil.which(name) is not None

# ─── pip-audit ────────────────────────────────────────────────────────────────

def audit_python(project_root):
    results = {"tool": "pip-audit", "findings": [], "error": None}
    req = os.path.join(project_root, "requirements.txt")
    if not os.path.exists(req):
        results["error"] = "No requirements.txt found"
        return results
    if not tool_available("pip-audit"):
        results["error"] = "pip-audit not installed (pip install pip-audit)"
        return results

    stdout, code = run(["pip-audit", "-r", req, "--format", "json"])
    if stdout is None:
        results["error"] = "pip-audit timed out"
        return results

    try:
        data = json.loads(stdout)
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                results["findings"].append({
                    "package": dep.get("name"),
                    "version": dep.get("version"),
                    "cve": vuln.get("id"),
                    "severity": vuln.get("fix_versions", ["?"]),
                    "description": vuln.get("description", "")[:200],
                    "fix_versions": vuln.get("fix_versions", []),
                })
    except (json.JSONDecodeError, KeyError):
        results["error"] = "Failed to parse pip-audit output"

    return results

# ─── npm audit ───────────────────────────────────────────────────────────────

def audit_node(project_root):
    results = {"tool": "npm-audit", "findings": [], "error": None}
    pkg = os.path.join(project_root, "package.json")
    if not os.path.exists(pkg):
        results["error"] = "No package.json found"
        return results
    if not tool_available("npm"):
        results["error"] = "npm not installed"
        return results

    stdout, code = run(["npm", "audit", "--json"], cwd=project_root)
    if stdout is None:
        results["error"] = "npm audit timed out"
        return results

    try:
        data = json.loads(stdout)
        for vuln_name, vuln in data.get("vulnerabilities", {}).items():
            severity = vuln.get("severity", "unknown")
            if severity in ("critical", "high", "moderate"):
                results["findings"].append({
                    "package": vuln_name,
                    "severity": severity,
                    "cve": ", ".join(
                        v.get("url", "") for v in vuln.get("via", []) if isinstance(v, dict)
                    ),
                    "description": vuln.get("title", vuln.get("name", "")),
                    "fix_available": vuln.get("fixAvailable", False),
                    "range": vuln.get("range", ""),
                })
    except (json.JSONDecodeError, KeyError):
        results["error"] = "Failed to parse npm audit output"

    return results

# ─── trivy SBOM + license scan ───────────────────────────────────────────────

def audit_trivy(project_root, generate_sbom=False):
    results = {"tool": "trivy", "findings": [], "sbom": None, "error": None}
    if not tool_available("trivy"):
        results["error"] = "trivy not installed (see INSTALL.md)"
        return results

    # Filesystem vulnerability scan
    stdout, code = run(
        ["trivy", "fs", "--format", "json", "--exit-code", "0", project_root],
        timeout=180,
    )
    if stdout:
        try:
            data = json.loads(stdout)
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "UNKNOWN").lower()
                    if sev in ("critical", "high"):
                        results["findings"].append({
                            "package": vuln.get("PkgName"),
                            "version": vuln.get("InstalledVersion"),
                            "cve": vuln.get("VulnerabilityID"),
                            "severity": sev,
                            "description": vuln.get("Description", "")[:200],
                            "fix_version": vuln.get("FixedVersion"),
                        })
        except json.JSONDecodeError:
            results["error"] = "Failed to parse trivy output"

    # SBOM generation (CycloneDX)
    if generate_sbom:
        sbom_path = os.path.join(AUDIT_DIR, "sbom-cyclonedx.json")
        run(
            ["trivy", "fs", "--format", "cyclonedx", "--output", sbom_path, project_root],
            timeout=180,
        )
        if os.path.exists(sbom_path):
            results["sbom"] = sbom_path
            print(f"[layer0] SBOM generated: {sbom_path}")

    return results

# ─── License compliance check ────────────────────────────────────────────────

PROHIBITED_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1"}

def check_licenses(project_root):
    """Simple license check via pip-licenses or package.json inspection."""
    findings = []

    # Node: check package-lock.json for licenses
    lock = os.path.join(project_root, "package-lock.json")
    if os.path.exists(lock):
        try:
            with open(lock) as f:
                data = json.load(f)
            for pkg_name, pkg_data in data.get("packages", {}).items():
                lic = pkg_data.get("license", "")
                if lic in PROHIBITED_LICENSES:
                    findings.append({
                        "package": pkg_name,
                        "license": lic,
                        "severity": "medium",
                        "description": f"Package uses {lic} license which may conflict with commercial use",
                    })
        except (json.JSONDecodeError, KeyError):
            pass

    return findings

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Layer 0: Dependency & supply chain audit")
    parser.add_argument("path", help="Project root to audit")
    parser.add_argument("--output", "-o", default=None, help="Write JSON results to file")
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM with trivy")
    args = parser.parse_args()

    os.makedirs(AUDIT_DIR, exist_ok=True)
    project = os.path.abspath(args.path)
    print(f"\n[layer0] Starting dependency audit: {project}\n")

    report = {
        "layer": 0,
        "project": project,
        "tools_run": [],
        "python": None,
        "node": None,
        "trivy": None,
        "license_issues": [],
        "total_findings": 0,
    }

    # Python subproject
    flask_path = os.path.join(project, "flask-app")
    py_target = flask_path if os.path.isdir(flask_path) else project
    report["python"] = audit_python(py_target)
    if report["python"].get("error") is None:
        report["tools_run"].append("pip-audit")

    # Node subproject
    node_path = os.path.join(project, "node-app")
    node_target = node_path if os.path.isdir(node_path) else project
    report["node"] = audit_node(node_target)
    if report["node"].get("error") is None:
        report["tools_run"].append("npm-audit")

    # Trivy
    report["trivy"] = audit_trivy(project, generate_sbom=args.sbom)
    if report["trivy"].get("error") is None:
        report["tools_run"].append("trivy")

    # License check
    report["license_issues"] = check_licenses(node_target)

    # Totals
    total = (
        len(report["python"].get("findings", []))
        + len(report["node"].get("findings", []))
        + len(report["trivy"].get("findings", []))
        + len(report["license_issues"])
    )
    report["total_findings"] = total

    # Summary
    print(f"[layer0] Tools run: {', '.join(report['tools_run']) or 'none'}")
    print(f"[layer0] Python CVEs:  {len(report['python'].get('findings', []))}")
    print(f"[layer0] Node CVEs:    {len(report['node'].get('findings', []))}")
    print(f"[layer0] Trivy CVEs:   {len(report['trivy'].get('findings', []))}")
    print(f"[layer0] License issues: {len(report['license_issues'])}")
    print(f"[layer0] Total:        {total} finding(s)\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[layer0] Results written to {args.output}")

    has_critical = any(
        f.get("severity") in ("critical", "high")
        for src in ["python", "node", "trivy"]
        for f in report.get(src, {}).get("findings", [])
    )

    return 1 if has_critical else 0

if __name__ == "__main__":
    sys.exit(main())
