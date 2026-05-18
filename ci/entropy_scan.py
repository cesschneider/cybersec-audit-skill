#!/usr/bin/env python3
"""
entropy_scan.py — Shannon entropy-based secret detection.

Scans source files for high-entropy strings that look like secrets even when
they aren't labeled (no 'api_key =' prefix needed). Complements grep-based
SecretScanner in SKILL.md Layer 1.

Also optionally scans git history for secrets committed and later deleted.

Usage:
  python ci/entropy_scan.py /path/to/project [--output results.json] [--git-history]
"""

import os
import re
import sys
import math
import json
import argparse
import subprocess

# ─── Configuration ───────────────────────────────────────────────────────────

# Minimum length for a string to be checked for entropy
MIN_TOKEN_LENGTH = 20

# Shannon entropy threshold (bits per character).
# English prose ~4.0, random strings ~5.0+, secrets typically >5.3
ENTROPY_THRESHOLD = 5.0

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go",
    ".java", ".php", ".env", ".yml", ".yaml", ".json",
    ".sh", ".bash", ".conf", ".cfg", ".toml",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "coverage", ".audit",
}

# String patterns to extract (quoted strings, assignment RHS, etc.)
TOKEN_PATTERNS = [
    re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']'),  # quoted values
    re.compile(r'=\s*([A-Za-z0-9+/=_\-]{20,})'),         # assignment RHS
]

# Ignore patterns (known safe values)
IGNORE_PATTERNS = [
    re.compile(r'^[a-zA-Z_]+$'),          # pure alphabetic (variable names, etc.)
    re.compile(r'^[0-9]+$'),              # pure numeric
    re.compile(r'example|placeholder|your[_-]?secret|changeme|todo|fixme',
               re.IGNORECASE),
    re.compile(r'^\$\{.*\}$|^process\.env\.|^os\.environ'),  # env var references
]

# ─── Shannon entropy ──────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())

def is_ignored(token: str) -> bool:
    return any(p.search(token) for p in IGNORE_PATTERNS)

# ─── File scanner ─────────────────────────────────────────────────────────────

def scan_file(path: str) -> list:
    findings = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                for pattern in TOKEN_PATTERNS:
                    for match in pattern.finditer(line):
                        token = match.group(1)
                        if len(token) < MIN_TOKEN_LENGTH:
                            continue
                        if is_ignored(token):
                            continue
                        entropy = shannon_entropy(token)
                        if entropy >= ENTROPY_THRESHOLD:
                            findings.append({
                                "file": path,
                                "line": lineno,
                                "token_preview": token[:8] + "..." + token[-4:],
                                "entropy": round(entropy, 3),
                                "severity": "critical" if entropy >= 5.5 else "high",
                                "description": (
                                    f"High-entropy string detected (entropy={entropy:.2f} ≥ {ENTROPY_THRESHOLD}). "
                                    "May be a hardcoded secret, key, or token."
                                ),
                                "source": "entropy_scan",
                            })
    except (OSError, PermissionError):
        pass
    return findings

def scan_directory(root: str) -> list:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            path = os.path.join(dirpath, filename)
            findings.extend(scan_file(path))
    return findings

# ─── Git history scan ─────────────────────────────────────────────────────────

def scan_git_history(repo_root: str) -> list:
    """Scan deleted/modified content in git history for high-entropy strings."""
    findings = []
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--diff-filter=M", "-p", "--no-color", "--follow", "--", "*.py", "*.js", "*.env"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        added_lines = [
            line[1:] for line in result.stdout.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        for lineno, line in enumerate(added_lines, 1):
            for pattern in TOKEN_PATTERNS:
                for match in pattern.finditer(line):
                    token = match.group(1)
                    if len(token) < MIN_TOKEN_LENGTH or is_ignored(token):
                        continue
                    entropy = shannon_entropy(token)
                    if entropy >= ENTROPY_THRESHOLD:
                        findings.append({
                            "file": "git-history",
                            "line": f"log-line-{lineno}",
                            "token_preview": token[:8] + "..." + token[-4:],
                            "entropy": round(entropy, 3),
                            "severity": "critical",
                            "description": (
                                "High-entropy string found in git history (may be a deleted secret). "
                                f"entropy={entropy:.2f}"
                            ),
                            "source": "git_history_scan",
                        })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return findings

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Entropy-based secret scanner")
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument("--output", "-o", default=None, help="Write JSON results to file")
    parser.add_argument("--git-history", action="store_true", help="Also scan git history")
    args = parser.parse_args()

    print(f"[entropy_scan] Scanning {args.path} (threshold={ENTROPY_THRESHOLD})")

    findings = scan_directory(args.path)

    if args.git_history:
        print("[entropy_scan] Scanning git history...")
        findings += scan_git_history(args.path)

    # De-duplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["line"], f["token_preview"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"[entropy_scan] {len(unique)} finding(s) found")
    for f in unique:
        print(f"  [{f['severity'].upper()}] {f['file']}:{f['line']} — entropy={f['entropy']} — {f['token_preview']}")

    if args.output:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
        with open(args.output, "w") as out:
            json.dump(unique, out, indent=2)
        print(f"[entropy_scan] Results written to {args.output}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
