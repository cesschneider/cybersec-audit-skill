// Vulnerable Go HTTP API — cybersecurity audit demo
// DO NOT USE IN PRODUCTION — intentionally contains security flaws.
//
// Vulnerabilities present (for audit training):
//   [CWE-89]  SQL injection via fmt.Sprintf in queries
//   [CWE-78]  Command injection via exec.Command with user input
//   [CWE-22]  Path traversal in file server
//   [CWE-798] Hardcoded credentials and secret key
//   [CWE-200] Debug endpoint exposing environment variables
//   [CWE-209] Error messages exposing internal details
//   [CWE-284] No authentication on admin endpoints
//   [CWE-79]  XSS via unescaped HTML template rendering
//   [CWE-330] Weak random number generation (math/rand not crypto/rand)
//   [CWE-327] MD5 used for password hashing

package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// [CWE-798] Hardcoded credentials — never do this
const (
	AdminPassword = "supersecret123"   // hardcoded admin password
	SecretKey     = "hardcoded-jwt-secret-key-do-not-use"
	DBPath        = "./demo.db"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite3", DBPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	setupDB()

	// [CWE-200] Bind to all interfaces, expose debug endpoint
	http.HandleFunc("/api/users/search", searchUsers)
	http.HandleFunc("/api/users/create", createUser)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/ping", pingHandler)
	http.HandleFunc("/api/files", fileHandler)
	http.HandleFunc("/api/greet", greetHandler)
	http.HandleFunc("/admin/env", debugEnvHandler)  // [CWE-200] exposes env vars
	http.HandleFunc("/admin/delete", adminDelete)   // [CWE-284] no auth

	rand.Seed(time.Now().UnixNano()) // [CWE-330] predictable seed

	fmt.Println("Vulnerable Go demo running on :8080")
	// [CWE-200] binds to 0.0.0.0 (all interfaces)
	http.ListenAndServe(":8080", nil)
}

func setupDB() {
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id       INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		email    TEXT NOT NULL,
		password TEXT NOT NULL,
		role     TEXT NOT NULL DEFAULT 'user'
	)`)
	// [CWE-327] passwords stored as MD5 hashes
	db.Exec(`INSERT OR IGNORE INTO users VALUES (1,'admin','admin@example.com','` +
		fmt.Sprintf("%x", md5.Sum([]byte(AdminPassword))) + `','admin')`)
	db.Exec(`INSERT OR IGNORE INTO users VALUES (2,'alice','alice@example.com','` +
		fmt.Sprintf("%x", md5.Sum([]byte("alice123"))) + `','user')`)
}

// [CWE-89] SQL injection — user input directly interpolated into query
func searchUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	// VULNERABLE: direct string interpolation
	query := fmt.Sprintf("SELECT id, username, email FROM users WHERE username LIKE '%%%s%%'", q)
	rows, err := db.Query(query)
	if err != nil {
		// [CWE-209] expose internal error
		http.Error(w, "DB error: "+err.Error(), 500)
		return
	}
	defer rows.Close()
	result := ""
	for rows.Next() {
		var id int
		var username, email string
		rows.Scan(&id, &username, &email)
		result += fmt.Sprintf("%d:%s:%s\n", id, username, email)
	}
	w.Write([]byte(result))
}

// [CWE-89] SQL injection in login + [CWE-327] MD5 password check
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
	// VULNERABLE: SQL injection in WHERE clause
	query := fmt.Sprintf(
		"SELECT id, role FROM users WHERE username='%s' AND password='%s'",
		username, hash,
	)
	row := db.QueryRow(query)
	var id int
	var role string
	if err := row.Scan(&id, &role); err != nil {
		http.Error(w, "Invalid credentials: "+err.Error(), 401) // [CWE-209]
		return
	}
	// [CWE-330] weak random token
	token := fmt.Sprintf("%d-%d", id, rand.Int63())
	w.Write([]byte(`{"token":"` + token + `","role":"` + role + `"}`))
}

// [CWE-78] Command injection — user input passed to shell command
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// VULNERABLE: no input validation — allows ; rm -rf / or similar
	out, err := exec.Command("sh", "-c", "ping -c 3 "+host).Output()
	if err != nil {
		http.Error(w, "Command error: "+err.Error(), 500)
		return
	}
	w.Write(out)
}

// [CWE-22] Path traversal — user controls file path
func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// VULNERABLE: no path sanitization — ../../etc/passwd works
	data, err := os.ReadFile("./uploads/" + name)
	if err != nil {
		http.Error(w, "File error: "+err.Error(), 404)
		return
	}
	w.Write(data)
}

// [CWE-79] XSS via unescaped HTML template
func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// VULNERABLE: template.HTML bypasses escaping
	tmpl := template.Must(template.New("greet").Parse(`<h1>Hello, {{.}}!</h1>`))
	w.Header().Set("Content-Type", "text/html")
	// Passing template.HTML allows raw HTML injection
	tmpl.Execute(w, template.HTML(name))
}

// [CWE-200] Debug endpoint exposing environment variables
func debugEnvHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: dumps all env vars including secrets
	for _, env := range os.Environ() {
		fmt.Fprintln(w, env)
	}
}

// [CWE-89] SQL injection in admin delete + [CWE-284] no auth check
func adminDelete(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: no authentication — anyone can call this
	id := r.URL.Query().Get("id")
	// VULNERABLE: direct interpolation
	query := fmt.Sprintf("DELETE FROM users WHERE id = %s", id)
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, "Delete error: "+err.Error(), 500)
		return
	}
	w.Write([]byte(`{"message":"deleted"}`))
}

// [CWE-89] SQL injection in user creation
func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	hash := fmt.Sprintf("%x", md5.Sum([]byte(password))) // [CWE-327]
	// VULNERABLE: SQL injection
	query := fmt.Sprintf(
		"INSERT INTO users (username, email, password) VALUES ('%s', '%s', '%s')",
		username, email, hash,
	)
	result, err := db.Exec(query)
	if err != nil {
		http.Error(w, "Insert error: "+err.Error(), 500)
		return
	}
	id, _ := result.LastInsertId()
	w.Write([]byte(fmt.Sprintf(`{"id":%d}`, id)))
}
