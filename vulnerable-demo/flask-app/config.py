"""Flask app configuration — SECURITY FIXED version."""

import os
import secrets

# [SECURITY FIX] CWE-798 — all secrets from environment variables
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DATABASE_URL = os.environ.get('DATABASE_URL')
API_SECRET = os.environ.get('API_SECRET')

# [SECURITY FIX] CWE-16 — debug off by default
DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

# [SECURITY FIX] CWE-16 — explicit allowed hosts
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# [SECURITY FIX] CWE-942 — explicit CORS origins
CORS_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')

# [SECURITY FIX] CWE-352 — secure and HttpOnly cookies enabled
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
