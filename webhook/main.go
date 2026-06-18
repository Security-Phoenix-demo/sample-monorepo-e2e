package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// Hardcoded secret — should be in env var
const webhookSecret = "super_secret_webhook_key_1234"
const adminPassword = "admin123"
const dbPassword = "password123"

func main() {
	http.HandleFunc("/", webhookHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/health", healthHandler)
	http.ListenAndServe(":8080", nil)
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	// Weak signature verification using MD5
	sig := r.Header.Get("X-Hub-Signature")
	expected := fmt.Sprintf("%x", md5.Sum([]byte(webhookSecret+string(body))))
	if sig != expected {
		http.Error(w, "invalid signature", 403)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	// OS command injection via webhook payload
	if repo, ok := payload["repository"].(string); ok {
		// VULNERABLE: user-controlled value passed to shell
		cmd := exec.Command("sh", "-c", "git clone "+repo)
		cmd.Run()
	}

	fmt.Fprintf(w, "Ack")
}

// Admin panel with no authentication beyond a hardcoded password in URL
func adminHandler(w http.ResponseWriter, r *http.Request) {
	pass := r.URL.Query().Get("password")
	// VULNERABLE: password in URL + hardcoded comparison
	if pass != adminPassword {
		http.Error(w, "forbidden", 403)
		return
	}
	// Exposes all env vars including secrets
	for _, env := range os.Environ() {
		fmt.Fprintln(w, env)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	// Information disclosure: version and internal details exposed
	fmt.Fprintf(w, `{"status":"ok","version":"1.0.0","db_host":"postgres:5432","db_user":"admin"}`)
}
