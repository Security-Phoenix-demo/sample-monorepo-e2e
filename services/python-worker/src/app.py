"""
Python worker service — intentionally vulnerable for security testing.
Vulnerabilities: pickle RCE, SSTI, SQLi, command injection, XXE, path traversal.
"""

import os
import pickle
import subprocess
import yaml
import sqlite3
import hashlib
from flask import Flask, request, jsonify, render_template_string
from xml.etree import ElementTree

app = Flask(__name__)

# Hardcoded credentials — never do this in production
DB_PATH = "/data/app.db"
SECRET_KEY = "hardcoded_flask_secret_key_abc123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

app.secret_key = SECRET_KEY


@app.route("/deserialize", methods=["POST"])
def deserialize():
    """Pickle deserialization RCE — attacker sends crafted pickle payload."""
    data = request.get_data()
    # VULNERABLE: unpickling untrusted data allows arbitrary code execution
    obj = pickle.loads(data)
    return jsonify({"result": str(obj)})


@app.route("/template")
def template():
    """Server-Side Template Injection via Jinja2."""
    name = request.args.get("name", "World")
    # VULNERABLE: user input directly in template string
    # PoC: /template?name={{config.items()}}
    tmpl = f"<h1>Hello {name}!</h1>"
    return render_template_string(tmpl)


@app.route("/query")
def query():
    """SQL injection — user input concatenated into raw SQL."""
    username = request.args.get("user", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # VULNERABLE: string formatting into SQL
    sql = f"SELECT id, username, email, password_hash FROM users WHERE username = '{username}'"
    try:
        cur.execute(sql)
        rows = cur.fetchall()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/run")
def run():
    """OS command injection via subprocess with shell=True."""
    cmd = request.args.get("cmd", "echo hello")
    # VULNERABLE: shell=True with user-controlled input
    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return result.decode()


@app.route("/yaml-load", methods=["POST"])
def yaml_load():
    """PyYAML arbitrary code execution (CVE-2017-18342 — yaml.load without Loader)."""
    content = request.get_data(as_text=True)
    # VULNERABLE: yaml.load() executes Python objects in YAML
    # PoC: !!python/object/apply:os.system ["id"]
    data = yaml.load(content)
    return jsonify(data)


@app.route("/xml", methods=["POST"])
def xml_parse():
    """XXE — external entity injection via XML parsing."""
    content = request.get_data(as_text=True)
    # VULNERABLE: ElementTree doesn't expand external entities but lxml does
    # Included as a pattern for scanners
    tree = ElementTree.fromstring(content)
    result = {child.tag: child.text for child in tree}
    return jsonify(result)


@app.route("/file")
def read_file():
    """Path traversal — arbitrary file read."""
    filename = request.args.get("path", "data.txt")
    # VULNERABLE: no path restriction — /file?path=../../etc/passwd
    with open(filename, "r") as f:
        return f.read()


@app.route("/hash")
def weak_hash():
    """Weak MD5 hashing of sensitive data."""
    data = request.args.get("data", "")
    # VULNERABLE: MD5 is cryptographically broken
    result = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"hash": result, "algorithm": "md5"})


@app.route("/redirect")
def open_redirect():
    """Open redirect — attacker controls destination URL."""
    from flask import redirect
    url = request.args.get("url", "/")
    # VULNERABLE: no whitelist check
    return redirect(url)


if __name__ == "__main__":
    # Debug mode enabled — exposes interactive debugger
    app.run(host="0.0.0.0", port=5000, debug=True)
