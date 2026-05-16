"""Vulnerable Flask demo application for security audit training.
DO NOT deploy — this has critical security issues on purpose.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

# BUG: Hardcoded credentials in source code
API_KEY = "sk-live-abc123def456ghi789jkl012mno345"
DATABASE_URL = "postgresql://admin:SuperSecretPassword123@db.internal:5432/production"
SECRET_KEY = 'this-is-a-hardcoded-secret-key'

# BUG: Debug enabled in production
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = SECRET_KEY

os.makedirs(os.path.join(os.path.dirname(__file__), 'uploads'), exist_ok=True)

def get_db():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/init')
def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, role TEXT)''')
    db.execute("INSERT OR IGNORE INTO users (id, username, email, password, role) VALUES (1, 'admin', 'admin@test.com', 'admin123', 'admin')")
    db.execute("INSERT OR IGNORE INTO users (id, username, email, password, role) VALUES (2, 'alice', 'alice@test.com', 'password456', 'user')")
    db.commit()
    return 'DB initialized (demo only)'

# BUG: SQL Injection — f-string in query
@app.route('/api/user')
def get_user():
    user_id = request.args.get('id', '1')
    db = get_db()
    # VULNERABLE: f-string directly in SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    user = db.execute(query).fetchone()
    return jsonify(dict(user)) if user else jsonify({"error": "Not found"}), 404

# BUG: SQL Injection — string concatenation
@app.route('/api/search')
def search_users():
    name = request.args.get('name', '')
    db = get_db()
    query = "SELECT * FROM users WHERE username LIKE '%" + name + "%'"
    users = db.execute(query).fetchall()
    return jsonify([dict(u) for u in users])

# BUG: SQL Injection — .format()
@app.route('/api/user-by-email')
def get_user_by_email():
    email = request.args.get('email', '')
    db = get_db()
    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    user = db.execute(query).fetchone()
    return jsonify(dict(user)) if user else (jsonify({"error": "Not found"}), 404)

# BUG: Command Injection — os.system with user input
@app.route('/api/ping', methods=['POST'])
def ping_host():
    host = request.json.get('host', '127.0.0.1')
    # VULNERABLE: user input directly in shell command
    os.system(f"ping -c 3 {host}")
    return jsonify({"status": "pinged"})

# BUG: Command Injection — subprocess with shell=True
@app.route('/api/diagnose', methods=['POST'])
def diagnose():
    target = request.json.get('target', 'localhost')
    # VULNERABLE: shell=True with unsanitized input
    result = subprocess.run(f"nslookup {target}", shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})

# BUG: XSS — reflected user input in HTML response
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # VULNERABLE: unescaped user input in HTML
    return f'<h1>Hello, {name}!</h1><p>Welcome to our app.</p>', 200, {'Content-Type': 'text/html'}

# BUG: Reflected XSS in error message
@app.route('/error-demo')
def error_demo():
    msg = request.args.get('msg', '')
    return f'<div class="error">Error: {msg}</div>', 400, {'Content-Type': 'text/html'}

# BUG: Path Traversal — user controls file path
@app.route('/api/download')
def download_file():
    filename = request.args.get('file', 'readme.txt')
    # VULNERABLE: no path sanitization, allows ../../
    return send_from_directory(os.path.dirname(__file__), filename)

# BUG: No authentication on admin route
@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # BUG: No auth check on admin endpoint
    db = get_db()
    db.execute(f"DELETE FROM users WHERE id = {user_id}")
    db.commit()
    return jsonify({"message": f"User {user_id} deleted"})

# BUG: Information disclosure in errors
@app.route('/api/profile', methods=['POST'])
def profile():
    try:
        user_id = request.json.get('user_id')
        db = get_db()
        # BUG: SQL injection again
        user = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
        return jsonify(dict(user))
    except Exception as e:
        # BUG: Full stack trace exposed
        import traceback
        return jsonify({
            "error": str(e),
            "type": type(e).__name__,
            "traceback": traceback.format_exc()
        }), 500

# BUG: Weak authentication — password comparison in SQL
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    db = get_db()
    # BUG: SQL injection + plaintext password comparison
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(query).fetchone()
    if user:
        return jsonify({"message": "Login successful", "user": dict(user)})
    return jsonify({"error": "Invalid credentials"}), 401

# BUG: CORS allows all origins
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    return response

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
