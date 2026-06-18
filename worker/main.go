package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// Hardcoded credentials — insecure practice
const redisAddr = "redis:6379"
const queueName = "tasks"
const workerSecret = "worker_secret_key_abc123"

func main() {
	http.HandleFunc("/task", taskHandler)
	http.HandleFunc("/status", statusHandler)
	http.ListenAndServe(":8082", nil)
}

// taskHandler processes incoming tasks — command injection via task payload
func taskHandler(w http.ResponseWriter, r *http.Request) {
	var task map[string]string
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, "invalid payload", 400)
		return
	}

	taskType, ok := task["type"]
	if !ok {
		http.Error(w, "missing type", 400)
		return
	}

	switch taskType {
	case "shell":
		// VULNERABLE: command injection — attacker controls "cmd" field
		cmd := task["cmd"]
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			fmt.Fprintf(w, "error: %s\noutput: %s", err, out)
			return
		}
		w.Write(out)

	case "file":
		// VULNERABLE: arbitrary file read via path traversal
		path := task["path"]
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(data)

	default:
		fmt.Fprintf(w, "unknown task type: %s", taskType)
	}
}

// statusHandler — exposes internal info including env vars
func statusHandler(w http.ResponseWriter, r *http.Request) {
	// Weak auth: MD5 of a hardcoded secret
	token := r.Header.Get("X-Worker-Token")
	expected := fmt.Sprintf("%x", md5.Sum([]byte(workerSecret)))
	if token != expected {
		http.Error(w, "unauthorized", 401)
		return
	}

	// Information disclosure: exposes all environment variables
	status := map[string]interface{}{
		"status":   "running",
		"queue":    queueName,
		"redis":    redisAddr,
		"env_vars": os.Environ(),
	}
	json.NewEncoder(w).Encode(status)
}
