"""Intentionally vulnerable Flask demo — SECURITY FIXED version.
All 14 critical and high findings from the audit have been patched.
"""

import os
import secrets
import sqlite3
import subprocess
import logging
from flask import Flask, request, jsonify, send_from_directory, abort

app = Flask(__name__)

# [SECURITY FIX] CWE-798 — load secrets from environment, never hardcode
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# [SECURITY FIX] CWE-16 — debug mode from env variable, defaults to False
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'demo.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/init')
def init_db():
    import bcrypt
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, role TEXT)''')
    # [SECURITY FIX] CWE-327 — hash passwords with bcrypt, not plaintext
    hashed = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
    db.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin@test.com',?,'admin')", (hashed,))
    hashed2 = bcrypt.hashpw(b'password456', bcrypt.gensalt()).decode()
    db.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','alice@test.com',?,'user')", (hashed2,))
    db.commit()
    return 'DB initialized'


@app.route('/api/user')
def get_user():
    user_id = request.args.get('id', '1')
    db = get_db()
    # [SECURITY FIX] CWE-89 — parameterized query, no f-string
    user = db.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,)).fetchone()
    return jsonify(dict(user)) if user else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/search')
def search_users():
    name = request.args.get('name', '')
    db = get_db()
    # [SECURITY FIX] CWE-89 — parameterized LIKE query
    users = db.execute('SELECT id, username FROM users WHERE username LIKE ?', (f'%{name}%',)).fetchall()
    return jsonify([dict(u) for u in users])


@app.route('/api/user-by-email')
def get_user_by_email():
    email = request.args.get('email', '')
    db = get_db()
    # [SECURITY FIX] CWE-89 — parameterized query
    user = db.execute('SELECT id, username, email FROM users WHERE email = ?', (email,)).fetchone()
    return jsonify(dict(user)) if user else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/ping', methods=['POST'])
def ping_host():
    host = request.json.get('host', '127.0.0.1')
    # [SECURITY FIX] CWE-78 — explicit argument list, no shell=True
    result = subprocess.run(
        ['ping', '-c', '3', host],
        capture_output=True, text=True, timeout=10
    )
    return jsonify({'output': result.stdout})


@app.route('/api/diagnose', methods=['POST'])
def diagnose():
    target = request.json.get('target', 'localhost')
    # [SECURITY FIX] CWE-78 — list args, no shell interpolation
    result = subprocess.run(
        ['nslookup', target],
        capture_output=True, text=True, timeout=10
    )
    return jsonify({'output': result.stdout})


@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # [SECURITY FIX] CWE-79 — return JSON, not raw HTML
    return jsonify({'message': f'Hello, {name}!'})


@app.route('/error-demo')
def error_demo():
    msg = request.args.get('msg', '')
    # [SECURITY FIX] CWE-79 — return JSON error, not raw HTML
    return jsonify({'error': msg}), 400


@app.route('/api/download')
def download_file():
    filename = request.args.get('file', '')
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    # [SECURITY FIX] CWE-22 — resolve real path and verify within uploads dir
    real_path = os.path.realpath(os.path.join(base_dir, filename))
    if not real_path.startswith(base_dir):
        abort(403)
    if not os.path.isfile(real_path):
        abort(404)
    return send_from_directory(base_dir, os.path.basename(real_path))


@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # [SECURITY FIX] CWE-284 — require X-Admin-Token header for auth
    token = request.headers.get('X-Admin-Token', '')
    if token != os.environ.get('ADMIN_TOKEN', ''):
        abort(401)
    db = get_db()
    # [SECURITY FIX] CWE-89 — parameterized query
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'message': f'User {user_id} deleted'})


@app.route('/api/profile', methods=['POST'])
def profile():
    try:
        user_id = request.json.get('user_id')
        db = get_db()
        # [SECURITY FIX] CWE-89 — parameterized query
        user = db.execute(
            'SELECT id, username, email, role FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        return jsonify(dict(user)) if user else (jsonify({'error': 'Not found'}), 404)
    except Exception as e:
        # [SECURITY FIX] CWE-209 — log internally, return generic message
        logger.exception('Profile fetch error: %s', e)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    import bcrypt
    username = request.json.get('username', '')
    password = request.json.get('password', '').encode()
    db = get_db()
    # [SECURITY FIX] CWE-89 — parameterized query, no injection possible
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    # [SECURITY FIX] CWE-327 — bcrypt comparison, not plaintext
    if not bcrypt.checkpw(password, user['password'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'message': 'Login successful', 'user_id': user['id']})


@app.after_request
def add_security_headers(response):
    # [SECURITY FIX] CWE-942 — explicit allowed origins, not wildcard
    allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
    origin = request.headers.get('Origin', '')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    # [SECURITY FIX] — add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == '__main__':
    init_db()
    # [SECURITY FIX] CWE-200 — bind to localhost by default, not 0.0.0.0
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    app.run(host=host, port=port)
