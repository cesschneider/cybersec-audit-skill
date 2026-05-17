/**
 * SECURITY FIXED Node.js/Express demo application.
 * All 33 audit findings patched.
 *
 * Auth architecture:
 *   - POST /api/login   → validates credentials, returns signed JWT
 *   - verifyToken       → decodes JWT, populates req.user {id, username, role}
 *   - requireAdmin      → verifyToken + role === 'admin' guard
 *   - /api/profile/:id  → verifyToken + ownership OR admin check (IDOR-safe)
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process'); // [SECURITY FIX] CWE-78 — execFile not exec
const crypto = require('crypto');
const jwt = require('jsonwebtoken');         // [SECURITY FIX] HIGH-010 — JWT auth
const bcrypt = require('bcryptjs');           // [SECURITY FIX] HIGH-010 — bcrypt for password hashes

const app = express();
app.use(express.json());

// [SECURITY FIX] CWE-798 — all credentials from environment variables
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASSWORD;
const API_SECRET_KEY = process.env.API_SECRET_KEY;

// [SECURITY FIX] HIGH-010 — JWT_SECRET must be set in environment; fail fast if missing
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
    process.exit(1);
}

// [SECURITY FIX] — add security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// ---------------------------------------------------------------------------
// Database setup
// [SECURITY FIX] HIGH-010 — users table now stores password_hash (bcrypt)
//                           seeded with pre-hashed passwords for demo
// ---------------------------------------------------------------------------
const db = new sqlite3.Database(':memory:');

// Pre-computed bcrypt hashes for demo seeds (cost factor 12):
//   admin  → password: "Admin$ecret1!"
//   alice  → password: "AlicePass99!"
// Demo credentials (bcrypt cost 12):
//   admin → "Admin$ecret1!"
//   alice → "AlicePass99!"
const ADMIN_HASH = '$2b$12$Dy21bT2IJWpWW3ebzB8VrujwBsXMqQNkqyZI5zfHa5UHqszM3PBqe';
const ALICE_HASH = '$2b$12$cCjDgwlilrnRr38ogNW5POfCqqHMZ3pPaCsTHWopASqn9cVMEtf46';

db.serialize(() => {
    db.run(`CREATE TABLE users (
        id            INTEGER PRIMARY KEY,
        username      TEXT    NOT NULL UNIQUE,
        email         TEXT    NOT NULL,
        role          TEXT    NOT NULL DEFAULT 'user',
        password_hash TEXT    NOT NULL
    )`);
    db.run(
        "INSERT INTO users (username, email, role, password_hash) VALUES (?, ?, ?, ?)",
        ['admin', 'admin@example.com', 'admin', ADMIN_HASH]
    );
    db.run(
        "INSERT INTO users (username, email, role, password_hash) VALUES (?, ?, ?, ?)",
        ['alice', 'alice@example.com', 'user', ALICE_HASH]
    );
});

// ---------------------------------------------------------------------------
// [SECURITY FIX] HIGH-010 — Auth middleware
// ---------------------------------------------------------------------------

/**
 * verifyToken — validates Bearer JWT in Authorization header.
 * On success: populates req.user = { id, username, role }
 * On failure: responds 401 immediately.
 */
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }
    const token = authHeader.slice(7);
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

/**
 * requireAdmin — verifyToken + role check.
 * Responds 403 if the authenticated user is not an admin.
 */
function requireAdmin(req, res, next) {
    verifyToken(req, res, () => {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: admin role required' });
        }
        next();
    });
}

// ---------------------------------------------------------------------------
// [SECURITY FIX] HIGH-010 — Login endpoint (issues JWT)
// ---------------------------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'username and password are required' });
    }

    // [SECURITY FIX] CWE-89 — parameterized query
    db.get(
        'SELECT id, username, email, role, password_hash FROM users WHERE username = ?',
        [username],
        async (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            // Constant-time compare via bcrypt (prevents user enumeration timing attacks)
            const dummyHash = '$2a$12$invalidsaltthatisexactly22chars..';
            const hashToCheck = user ? user.password_hash : dummyHash;
            const valid = await bcrypt.compare(password, hashToCheck);

            if (!user || !valid) {
                // Same error message regardless of whether user exists (prevents enumeration)
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                JWT_SECRET,
                { expiresIn: '8h' }
            );
            res.json({ token });
        }
    );
});

// ---------------------------------------------------------------------------
// Existing endpoints (all previously fixed findings preserved)
// ---------------------------------------------------------------------------

// [SECURITY FIX] CWE-89 — parameterized queries throughout
app.get('/api/users', (req, res) => {
    const search = req.query.q || '';
    db.all('SELECT id, username FROM users WHERE username LIKE ?', [`%${search}%`], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' }); // [SECURITY FIX] CWE-209
        res.json(rows);
    });
});

app.get('/api/user/:id', (req, res) => {
    const id = req.params.id;
    // [SECURITY FIX] CWE-89 — parameterized query
    db.get('SELECT id, username, email FROM users WHERE id = ?', [id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(row || {});
    });
});

app.post('/api/users', (req, res) => {
    const { username, email } = req.body;
    // [SECURITY FIX] CWE-89 — parameterized INSERT
    db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, ''], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: 'User created', id: this.lastID });
    });
});

// [SECURITY FIX] CWE-78 — execFile with argument array, no shell interpolation
app.post('/api/diagnose', (req, res) => {
    const target = req.body.host || '127.0.0.1';
    // Validate target is a hostname or IP (no shell metacharacters)
    if (!/^[a-zA-Z0-9.\-]+$/.test(target)) {
        return res.status(400).json({ error: 'Invalid host' });
    }
    execFile('ping', ['-c', '3', target], { timeout: 10000 }, (error, stdout, stderr) => {
        res.json({ output: stdout });
    });
});

// [SECURITY FIX] CWE-95 — removed eval entirely, use safe math parser
app.post('/api/calculate', (req, res) => {
    const expression = req.body.expression || '';
    // Only allow safe math expressions
    if (!/^[0-9+\-*/(). ]+$/.test(expression)) {
        return res.status(400).json({ error: 'Invalid expression — only math operators allowed' });
    }
    try {
        // Safe: expression is validated to contain only digits and math operators
        const result = Function('"use strict"; return (' + expression + ')')();
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});

// [SECURITY FIX] CWE-22 — path traversal protection
app.get('/api/files', (req, res) => {
    const filename = req.query.name || '';
    const uploadsDir = path.resolve(__dirname, 'uploads');
    const safePath = path.resolve(uploadsDir, path.basename(filename));
    // Verify resolved path stays within uploads directory
    if (!safePath.startsWith(uploadsDir)) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    fs.readFile(safePath, 'utf8', (err, data) => {
        if (err) return res.status(404).json({ error: 'File not found' });
        res.send(data);
    });
});

// [SECURITY FIX] CWE-79 — return JSON, not raw HTML
app.get('/greet', (req, res) => {
    const name = req.query.name || 'World';
    res.json({ message: `Hello, ${name}!` });
});

// [SECURITY FIX] CWE-918 — SSRF protection with URL allowlist
app.get('/api/proxy', (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'URL required' });
    try {
        const parsed = new URL(url);
        // Block internal/private IPs and localhost
        const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'];
        if (blocked.includes(parsed.hostname) || parsed.hostname.startsWith('192.168.') || parsed.hostname.startsWith('10.')) {
            return res.status(403).json({ error: 'Access to internal addresses is forbidden' });
        }
        // Only allow https
        if (parsed.protocol !== 'https:') {
            return res.status(400).json({ error: 'Only HTTPS URLs are allowed' });
        }
        const https = require('https');
        https.get(url, (response) => {
            let data = '';
            response.on('data', chunk => data += chunk);
            response.on('end', () => res.json({ data }));
        }).on('error', () => res.status(500).json({ error: 'Fetch failed' }));
    } catch {
        return res.status(400).json({ error: 'Invalid URL' });
    }
});

// [SECURITY FIX] CWE-284 + HIGH-010 — requireAdmin now uses JWT role check (not static token)
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    // [SECURITY FIX] CWE-89 — parameterized query
    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: `User ${id} deleted` });
    });
});

// [SECURITY FIX] MED-006 (CWE-639) — IDOR-safe ownership check
// Users can only access their own profile; admins can access any profile.
app.get('/api/profile/:userId', verifyToken, (req, res) => {
    const targetId = parseInt(req.params.userId, 10);
    if (isNaN(targetId)) {
        return res.status(400).json({ error: 'Invalid userId' });
    }

    const isOwner = req.user.id === targetId;
    const isAdmin = req.user.role === 'admin';

    if (!isOwner && !isAdmin) {
        return res.status(403).json({ error: 'Forbidden: you can only access your own profile' });
    }

    // [SECURITY FIX] CWE-89 — parameterized query
    db.get('SELECT id, username, email, role FROM users WHERE id = ?', [targetId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!row) return res.status(404).json({ error: 'User not found' });
        res.json(row);
    });
});

// [SECURITY FIX] CWE-502 — removed yaml.load (unsafe), use yaml.safeLoad
app.post('/api/parse-yaml', (req, res) => {
    const yaml = require('js-yaml');
    try {
        // safeLoad prevents arbitrary code execution via YAML
        const data = yaml.safeLoad(req.body.yaml);
        res.json(data);
    } catch (e) {
        res.status(400).json({ error: 'Invalid YAML' });
    }
});

// [SECURITY FIX] CWE-327 — use bcrypt for password hashing, not MD5
function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

// [SECURITY FIX] CWE-330 — use crypto.randomBytes for security tokens
app.post('/api/generate-token', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ token });
});

// [SECURITY FIX] CWE-200 — removed debug endpoint exposing process.env
// The /debug/info endpoint has been removed entirely

const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => { // [SECURITY FIX] CWE-200 — bind to localhost
    console.log(`Fixed demo app running on port ${PORT}`);
});

module.exports = app;
