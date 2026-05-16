/**
 * Vulnerable Node.js Express demo application for security audit training.
 * DO NOT deploy — this has critical security issues on purpose.
 */

const express = require('express');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// BUG: Hardcoded credentials in source code
const DB_HOST = 'db.production.internal';
const DB_USER = 'admin';
const DB_PASS = 'Pr0duction_Passw0rd!2024';
const DB_NAME = 'webapp';
const API_SECRET_KEY = 'sk-live-prod-key-9876543210abcdef';

// BUG: No rate limiting middleware

// Database connection (lazy)
let pool;
async function getPool() {
    if (!pool) {
        pool = mysql.createPool({
            host: DB_HOST,
            user: DB_USER,
            password: DB_PASS,
            database: DB_NAME
        });
    }
    return pool;
}

// BUG: SQL Injection — template literal in query
app.get('/api/users', async (req, res) => {
    const search = req.query.q || '';
    const db = await getPool();
    // VULNERABLE: template literal directly in SQL
    const [rows] = await db.query(`SELECT * FROM users WHERE username LIKE '%${search}%'`);
    res.json(rows);
});

// BUG: SQL Injection — string concatenation
app.get('/api/user/:id', async (req, res) => {
    const id = req.params.id;
    const db = await getPool();
    // VULNERABLE: concatenation in SQL
    const [rows] = await db.query("SELECT * FROM users WHERE id = " + id);
    res.json(rows[0] || {});
});

// BUG: SQL Injection — unparameterized INSERT
app.post('/api/users', async (req, res) => {
    const { username, email } = req.body;
    const db = await getPool();
    await db.query(`INSERT INTO users (username, email) VALUES ('${username}', '${email}')`);
    res.json({ message: 'User created' });
});

// BUG: Command Injection — user input in exec
app.post('/api/diagnose', async (req, res) => {
    const target = req.body.host || '127.0.0.1';
    // VULNERABLE: user input passed directly to shell
    exec(`ping -c 3 ${target}`, (error, stdout, stderr) => {
        res.json({ output: stdout, error: stderr });
    });
});

// BUG: eval() with user-controlled input
app.post('/api/calculate', async (req, res) => {
    const expression = req.body.expression;
    try {
        // VULNERABLE: eval executes arbitrary code
        const result = eval(expression);
        res.json({ result });
    } catch (e) {
        // BUG: Stack trace leaked
        res.status(500).json({ error: e.message, stack: e.stack });
    }
});

// BUG: Path Traversal — user controls file path
app.get('/api/files', async (req, res) => {
    const filename = req.query.name;
    // VULNERABLE: no path sanitization, allows ../../
    const filePath = path.join(__dirname, 'uploads', filename);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).json({ error: 'File not found' });
        res.send(data);
    });
});

// BUG: Reflected XSS — unescaped user input in HTML
app.get('/greet', async (req, res) => {
    const name = req.query.name || 'World';
    // VULNERABLE: user input directly in HTML without escaping
    res.send(`<h1>Hello, ${name}!</h1><p>Welcome to our application.</p>`);
});

// BUG: SSRF — user controls the URL being fetched
app.get('/api/proxy', async (req, res) => {
    const url = req.query.url;
    // VULNERABLE: no URL validation, can access internal services
    const https = require('https');
    https.get(url, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => res.json({ data: JSON.parse(data) }));
    }).on('error', (e) => res.status(500).json({ error: e.message }));
});

// BUG: No authentication on admin routes
app.delete('/api/admin/users/:id', async (req, res) => {
    const id = req.params.id;
    const db = await getPool();
    // BUG: SQL injection + no auth check
    await db.query(`DELETE FROM users WHERE id = ${id}`);
    res.json({ message: `User ${id} deleted` });
});

// BUG: Insecure direct object reference (IDOR)
app.get('/api/profile/:userId', async (req, res) => {
    const userId = req.params.userId;
    const db = await getPool();
    // BUG: No check that requesting user owns this profile
    const [rows] = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
    res.json(rows[0] || {});
});

// BUG: Deserialization with user input
app.post('/api/parse-yaml', async (req, res) => {
    const yaml = require('js-yaml');
    try {
        const data = yaml.load(req.body.yaml);
        res.json(data);
    } catch (e) {
        res.status(400).json({ error: 'Invalid YAML' });
    }
});

// BUG: Weak password hashing
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// BUG: Using Math.random for security
app.post('/api/generate-token', async (req, res) => {
    const token = Math.random().toString(36).substring(2, 15);
    res.json({ token });
});

// BUG: Debug endpoint exposes system info
app.get('/debug/info', async (req, res) => {
    res.json({
        env: process.env,
        platform: process.platform,
        version: process.version,
        memory: process.memoryUsage(),
        uptime: process.uptime()
    });
});

// BUG: No Content-Security-Policy, no X-Frame-Options
// No helmet middleware, no security headers at all

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Vulnerable demo app running on port ${PORT}`);
});

module.exports = app;
