"""
security_regression.py — Security regression test suite for Flask demo app.

These tests run against the FIXED Flask app and confirm that all patched
vulnerabilities are NOT re-introduced. If any test fails, the CI gate blocks
the merge.

Run with:
  pip install pytest requests flask
  python -m pytest vulnerable-demo/flask-app/tests/security_regression.py -v

NOTE: Tests import the fixed app module directly (no server needed).
      The fixed app lives in vulnerable-demo/flask-app/app.py on the
      autofix-security-fixes branch. On main (intentionally vulnerable),
      many of these tests will intentionally FAIL — that's expected and
      demonstrates the audit's value.
"""

import os
import sys
import json
import re
import pytest

# ─── Path setup ──────────────────────────────────────────────────────────────
# Ensure we can import the flask app
FLASK_APP_DIR = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(FLASK_APP_DIR))

# ─── Deterministic pattern checks (no app import needed) ─────────────────────
# These grep-equivalent checks confirm dangerous patterns are absent in source.

APP_SRC = os.path.join(FLASK_APP_DIR, "app.py")
CONFIG_SRC = os.path.join(FLASK_APP_DIR, "config.py")
UTILS_SRC = os.path.join(FLASK_APP_DIR, "utils.py")


def read_source(*paths):
    combined = ""
    for path in paths:
        if os.path.exists(path):
            with open(path) as f:
                combined += f.read()
    return combined


# ─── CWE-89: SQL Injection ────────────────────────────────────────────────────

class TestSQLInjection:
    """Verify no raw string interpolation in SQL queries."""

    def test_no_fstring_sql(self):
        src = read_source(APP_SRC)
        # f"...SQL..." patterns
        matches = re.findall(r'f["\'].*SELECT.*\{.*\}', src, re.IGNORECASE)
        assert not matches, f"f-string SQL found: {matches}"

    def test_no_format_sql(self):
        src = read_source(APP_SRC)
        matches = re.findall(r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', src, re.IGNORECASE)
        assert not matches, f"str.format() in SQL found: {matches}"

    def test_no_concat_sql(self):
        src = read_source(APP_SRC)
        # "SELECT " + var patterns
        matches = re.findall(r'["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\'] *\+', src, re.IGNORECASE)
        assert not matches, f"String concat SQL found: {matches}"


# ─── CWE-78: Command Injection ────────────────────────────────────────────────

class TestCommandInjection:
    """Verify no unsafe shell execution patterns."""

    def test_no_os_system(self):
        src = read_source(APP_SRC)
        assert "os.system(" not in src, "os.system() found — use subprocess with arg list"

    def test_no_shell_true(self):
        src = read_source(APP_SRC)
        assert "shell=True" not in src, "subprocess shell=True found"

    def test_no_eval(self):
        src = read_source(APP_SRC, UTILS_SRC)
        # Allow eval in comments
        matches = re.findall(r'(?<!#)\beval\(', src)
        assert not matches, f"eval() usage found: {matches}"


# ─── CWE-798: Hardcoded Secrets ──────────────────────────────────────────────

class TestHardcodedSecrets:
    """Verify no credentials are baked into source code."""

    def test_no_hardcoded_api_key(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        # Should reference os.environ, not literal strings
        matches = re.findall(r'API_KEY\s*=\s*["\'][^"\']{8,}["\']', src)
        assert not matches, f"Hardcoded API key found: {matches}"

    def test_no_hardcoded_secret_key(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        matches = re.findall(r'SECRET_KEY\s*=\s*["\'][^"\']{8,}["\']', src)
        assert not matches, f"Hardcoded SECRET_KEY found: {matches}"

    def test_no_hardcoded_db_password(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        matches = re.findall(r'://[^:]+:[^@]{3,}@', src)  # user:pass@host pattern
        assert not matches, f"Hardcoded DB password in URL found: {matches}"

    def test_secrets_from_env(self):
        src = read_source(CONFIG_SRC if os.path.exists(CONFIG_SRC) else APP_SRC)
        assert "os.environ" in src, "Secrets should be loaded from environment variables"


# ─── CWE-16: Debug Mode ──────────────────────────────────────────────────────

class TestDebugMode:
    """Verify DEBUG is not hardcoded to True."""

    def test_no_debug_true(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        matches = re.findall(r"DEBUG\s*=\s*True", src)
        assert not matches, "DEBUG=True hardcoded — must read from env var"


# ─── CWE-327: Weak Cryptography ──────────────────────────────────────────────

class TestWeakCrypto:
    """Verify no MD5/SHA1 for passwords, no weak RNG."""

    def test_no_md5_passwords(self):
        src = read_source(UTILS_SRC if os.path.exists(UTILS_SRC) else APP_SRC)
        # Allow md5 in comments
        matches = re.findall(r'(?<!#)hashlib\.md5|(?<!#)md5\.new', src)
        assert not matches, f"MD5 password hashing found: {matches}"

    def test_no_random_for_tokens(self):
        src = read_source(UTILS_SRC if os.path.exists(UTILS_SRC) else APP_SRC)
        matches = re.findall(r'random\.randint|random\.random\(\)', src)
        assert not matches, f"Weak random (math/random) used for tokens: {matches}"

    def test_uses_secure_rng(self):
        src = read_source(UTILS_SRC if os.path.exists(UTILS_SRC) else APP_SRC)
        assert "secrets" in src or "bcrypt" in src, \
            "Should use secrets module or bcrypt for secure random/hashing"


# ─── CWE-502: Insecure Deserialization ───────────────────────────────────────

class TestDeserialization:
    """Verify pickle.loads is not used on untrusted data."""

    def test_no_pickle_loads(self):
        src = read_source(APP_SRC, UTILS_SRC)
        matches = re.findall(r'pickle\.loads\(', src)
        assert not matches, f"pickle.loads() found — use json.loads() instead: {matches}"


# ─── CWE-942: CORS ───────────────────────────────────────────────────────────

class TestCORSPolicy:
    """Verify CORS wildcard is not set."""

    def test_no_cors_wildcard(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        matches = re.findall(r'origins\s*=\s*["\']\*["\']|CORS_ORIGINS\s*=\s*["\']\*["\']', src)
        assert not matches, f"CORS wildcard (*) found: {matches}"


# ─── CWE-352: Cookie Security ────────────────────────────────────────────────

class TestCookieSecurity:
    """Verify session cookies are marked secure and httponly."""

    def test_session_cookie_secure(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        # Must have SESSION_COOKIE_SECURE = True somewhere
        has_secure = bool(re.search(r'SESSION_COOKIE_SECURE\s*=\s*True', src))
        has_env = bool(re.search(r'SESSION_COOKIE_SECURE.*environ', src))
        assert has_secure or has_env, "SESSION_COOKIE_SECURE must be True"

    def test_session_cookie_httponly(self):
        src = read_source(APP_SRC, CONFIG_SRC)
        has_httponly = bool(re.search(r'SESSION_COOKIE_HTTPONLY\s*=\s*True', src))
        has_env = bool(re.search(r'SESSION_COOKIE_HTTPONLY.*environ', src))
        assert has_httponly or has_env, "SESSION_COOKIE_HTTPONLY must be True"


# ─── CWE-209: Error Information Disclosure ───────────────────────────────────

class TestErrorHandling:
    """Verify stack traces are not exposed to clients."""

    def test_no_raw_exception_in_response(self):
        src = read_source(APP_SRC)
        # Look for patterns like jsonify({"error": str(e)}) or return str(e)
        matches = re.findall(r'str\(e\)|traceback\.format_exc\(\)', src)
        assert not matches, f"Raw exception string in response: {matches}"


# ─── Security Headers ────────────────────────────────────────────────────────

class TestSecurityHeaders:
    """Verify security headers are set."""

    def test_security_headers_present(self):
        src = read_source(APP_SRC)
        assert "X-Content-Type-Options" in src, "Missing X-Content-Type-Options header"
        assert "X-Frame-Options" in src, "Missing X-Frame-Options header"
