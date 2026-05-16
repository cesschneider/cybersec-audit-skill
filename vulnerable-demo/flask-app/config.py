"""Flask app configuration — intentionally insecure for demo purposes."""

# VULNERABILITY: Hardcoded secrets
SECRET_KEY = 'flask-secret-key-hardcoded-2024'
DATABASE_URL = 'postgresql://root:root_password_123@localhost:5432/myapp'
API_SECRET = 'sk-proj-5f7a9b2c3d4e6f8a1b2c3d4e5f6a7b8c'

# VULNERABILITY: Debug mode in production
DEBUG = True

# VULNERABILITY: Empty allowed hosts
ALLOWED_HOSTS = []

# VULNERABILITY: CORS allows all origins
CORS_ALLOW_ALL = True

# VULNERABILITY: Insecure session cookies
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
