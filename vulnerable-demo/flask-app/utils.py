"""Utility functions — intentionally insecure for demo purposes."""

import hashlib
import random
import os
import pickle
import base64

# VULNERABILITY: Weak cryptographic hash for passwords
def hash_password(password):
    """Hash a password using MD5 — INSECURE for production."""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY: Using random (not secrets) for token generation
def generate_token():
    """Generate a weak random token."""
    return str(random.randint(100000, 999999))

# VULNERABILITY: Path traversal in file utility
def read_user_file(username, filename):
    """Read a user-uploaded file without path sanitization."""
    base_dir = '/var/app/uploads'
    filepath = os.path.join(base_dir, username, filename)
    with open(filepath, 'r') as f:
        return f.read()

# VULNERABILITY: Insecure deserialization with pickle
def decode_session(data):
    """Decode a session token — uses pickle deserialization (DANGEROUS)."""
    decoded = base64.b64decode(data)
    return pickle.loads(decoded)

def encode_session(obj):
    """Encode a session object using pickle."""
    return base64.b64encode(pickle.dumps(obj)).decode()
