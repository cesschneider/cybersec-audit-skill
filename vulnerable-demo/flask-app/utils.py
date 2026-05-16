"""Utility functions — SECURITY FIXED version."""

import os
import secrets
import logging

logger = logging.getLogger(__name__)

# [SECURITY FIX] CWE-327 — use bcrypt for password hashing, not MD5
def hash_password(password: str) -> str:
    """Hash a password using bcrypt — secure for production."""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a bcrypt-hashed password."""
    import bcrypt
    return bcrypt.checkpw(password.encode(), hashed.encode())


# [SECURITY FIX] CWE-330 — use secrets module for cryptographic randomness
def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(length)


# [SECURITY FIX] CWE-22 — path traversal protection
def read_user_file(username: str, filename: str) -> str:
    """Read a user-uploaded file with path sanitization."""
    base_dir = os.path.realpath('/var/app/uploads')
    # Sanitize both username and filename
    safe_username = os.path.basename(username)
    safe_filename = os.path.basename(filename)
    filepath = os.path.realpath(os.path.join(base_dir, safe_username, safe_filename))
    # Ensure the resolved path is within the base directory
    if not filepath.startswith(base_dir):
        raise ValueError('Path traversal detected')
    with open(filepath, 'r') as f:
        return f.read()


# [SECURITY FIX] CWE-502 — removed pickle deserialization entirely
# Use JSON for safe serialization instead
import json
import base64

def encode_session(obj: dict) -> str:
    """Encode a session object using JSON (safe)."""
    return base64.b64encode(json.dumps(obj).encode()).decode()


def decode_session(data: str) -> dict:
    """Decode a JSON session token (safe)."""
    decoded = base64.b64decode(data)
    return json.loads(decoded)
