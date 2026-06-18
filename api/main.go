package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	http.HandleFunc("/", helloHandler)
	http.HandleFunc("/exec", execHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/fetch", fetchHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.ListenAndServe(":8080", nil)
}

// XSS: user input reflected directly without escaping
func helloHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", name)
}

// OS Command Injection: user-controlled input passed to shell
func execHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// VULNERABLE: direct shell execution of user input — /exec?cmd=id;cat+/etc/passwd
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s\nOutput: %s", err.Error(), out)
		return
	}
	w.Write(out)
}

// Path Traversal: user-supplied path not validated — /file?path=../../../../etc/passwd
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("path")
	data, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, "file read error: "+err.Error(), 500)
		return
	}
	w.Write(data)
}

// SSRF: user controls the URL fetched by the server — /fetch?url=http://169.254.169.254/latest/meta-data/
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "fetch error: "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// Insecure file upload: no type checking, predictable path, filename from user
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "upload error", 500)
		return
	}
	defer file.Close()
	os.MkdirAll("/tmp/uploads", 0777)
	// VULNERABLE: no extension check, path traversal via filename
	dst, _ := os.Create(filepath.Join("/tmp/uploads", header.Filename))
	defer dst.Close()
	io.Copy(dst, file)
	fmt.Fprintf(w, "Uploaded to /tmp/uploads/%s", header.Filename)
}
