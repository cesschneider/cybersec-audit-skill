/**
 * Integration tests for HIGH-010 (JWT auth) and MED-006 (IDOR protection).
 * Run with: node tests/auth.test.js
 * Requires: JWT_SECRET env var set (uses a test secret if not set)
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-for-ci-only-not-production';

const http = require('http');
const app = require('../server');

// ─── Minimal test harness ────────────────────────────────────────────────────
let passed = 0;
let failed = 0;

function assert(condition, label) {
    if (condition) {
        console.log(`  ✅ PASS: ${label}`);
        passed++;
    } else {
        console.error(`  ❌ FAIL: ${label}`);
        failed++;
    }
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────
function request(server, method, path, body, headers = {}) {
    return new Promise((resolve, reject) => {
        const addr = server.address();
        const bodyStr = body ? JSON.stringify(body) : '';
        const opts = {
            hostname: '127.0.0.1',
            port: addr.port,
            path,
            method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(bodyStr),
                ...headers,
            },
        };
        const req = http.request(opts, res => {
            let data = '';
            res.on('data', chunk => (data += chunk));
            res.on('end', () => {
                let json;
                try { json = JSON.parse(data); } catch { json = data; }
                resolve({ status: res.statusCode, body: json });
            });
        });
        req.on('error', reject);
        req.write(bodyStr);
        req.end();
    });
}

// ─── Test runner ─────────────────────────────────────────────────────────────
async function runTests() {
    const server = app.listen(0, '127.0.0.1'); // random free port
    await new Promise(r => server.once('listening', r));

    console.log('\n══════════════════════════════════════════════');
    console.log('  Auth & IDOR Security Tests');
    console.log('══════════════════════════════════════════════\n');

    // ── 1. Login endpoint ────────────────────────────────────────────────────
    console.log('▶ POST /api/login');

    const loginOk = await request(server, 'POST', '/api/login', {
        username: 'admin',
        password: 'Admin$ecret1!',
    });
    assert(loginOk.status === 200, 'admin login returns 200');
    assert(typeof loginOk.body.token === 'string', 'response contains a JWT token');

    const adminToken = loginOk.body.token;

    const aliceLogin = await request(server, 'POST', '/api/login', {
        username: 'alice',
        password: 'AlicePass99!',
    });
    assert(aliceLogin.status === 200, 'alice login returns 200');
    const aliceToken = aliceLogin.body.token;

    const badLogin = await request(server, 'POST', '/api/login', {
        username: 'admin',
        password: 'wrongpassword',
    });
    assert(badLogin.status === 401, 'wrong password returns 401');
    assert(badLogin.body.error === 'Invalid credentials', 'error message does not enumerate user existence');

    const unknownLogin = await request(server, 'POST', '/api/login', {
        username: 'nobody',
        password: 'whatever',
    });
    assert(unknownLogin.status === 401, 'unknown user returns 401 (not 404 — no user enumeration)');
    assert(unknownLogin.body.error === 'Invalid credentials', 'same error message for unknown user');

    const missingFields = await request(server, 'POST', '/api/login', {});
    assert(missingFields.status === 400, 'missing credentials returns 400');

    // ── 2. Protected admin endpoint (HIGH-010) ───────────────────────────────
    console.log('\n▶ DELETE /api/admin/users/:id  [HIGH-010 — requireAdmin with JWT]');

    const noToken = await request(server, 'DELETE', '/api/admin/users/99', null);
    assert(noToken.status === 401, 'no token → 401');

    const badToken = await request(server, 'DELETE', '/api/admin/users/99', null, {
        Authorization: 'Bearer this.is.invalid',
    });
    assert(badToken.status === 401, 'invalid token → 401');

    const aliceTriesAdmin = await request(server, 'DELETE', '/api/admin/users/99', null, {
        Authorization: `Bearer ${aliceToken}`,
    });
    assert(aliceTriesAdmin.status === 403, 'non-admin JWT → 403');

    const adminDeletes = await request(server, 'DELETE', '/api/admin/users/999', null, {
        Authorization: `Bearer ${adminToken}`,
    });
    // 200 (deleted) or 200 with message — sqlite returns success even if no row matched
    assert([200, 404].includes(adminDeletes.status), 'admin JWT → allowed through auth layer');

    // ── 3. Profile endpoint — IDOR (MED-006) ────────────────────────────────
    console.log('\n▶ GET /api/profile/:userId  [MED-006 — IDOR ownership check]');

    const noTokenProfile = await request(server, 'GET', '/api/profile/1', null);
    assert(noTokenProfile.status === 401, 'unauthenticated → 401');

    // alice is user id=2, admin is user id=1 (insertion order in seed)
    // alice should be able to access her own profile
    const aliceOwnProfile = await request(server, 'GET', '/api/profile/2', null, {
        Authorization: `Bearer ${aliceToken}`,
    });
    assert(aliceOwnProfile.status === 200, "alice can access her own profile (id=2)");
    assert(aliceOwnProfile.body.username === 'alice', "profile returns correct username");

    // alice should NOT be able to access admin's profile (id=1)
    const aliceAccessesAdmin = await request(server, 'GET', '/api/profile/1', null, {
        Authorization: `Bearer ${aliceToken}`,
    });
    assert(aliceAccessesAdmin.status === 403, 'alice cannot access admin profile → 403 (IDOR blocked)');
    assert(
        aliceAccessesAdmin.body.error.includes('own profile'),
        'error message explains ownership restriction'
    );

    // admin should be able to access any profile
    const adminAccessesAlice = await request(server, 'GET', '/api/profile/2', null, {
        Authorization: `Bearer ${adminToken}`,
    });
    assert(adminAccessesAlice.status === 200, 'admin can access any profile');

    const adminAccessesSelf = await request(server, 'GET', '/api/profile/1', null, {
        Authorization: `Bearer ${adminToken}`,
    });
    assert(adminAccessesSelf.status === 200, 'admin can access own profile');

    const profileNotFound = await request(server, 'GET', '/api/profile/9999', null, {
        Authorization: `Bearer ${adminToken}`,
    });
    assert(profileNotFound.status === 404, 'non-existent userId → 404');

    const invalidId = await request(server, 'GET', '/api/profile/abc', null, {
        Authorization: `Bearer ${adminToken}`,
    });
    assert(invalidId.status === 400, 'non-numeric userId → 400');

    // ── Summary ──────────────────────────────────────────────────────────────
    console.log('\n══════════════════════════════════════════════');
    console.log(`  Results: ${passed} passed, ${failed} failed`);
    console.log('══════════════════════════════════════════════\n');

    server.close();
    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
