#!/usr/bin/env python3
"""
ACME Internal Admin Portal
==========================
Author copy — includes full source and vulnerability notes.

INTENTIONALLY VULNERABLE APPLICATION — FOR EDUCATIONAL PURPOSES ONLY
This application is designed to demonstrate OS command injection vulnerabilities.
DO NOT deploy in a production environment.
"""

import subprocess
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/tools")
def tools():
    return render_template("tools.html")


@app.route("/logs")
def logs():
    with open("fake_data/logs.txt", "r") as f:
        log_content = f.read()
    return render_template("logs.html", logs=log_content)


@app.route("/about")
def about():
    return render_template("about.html")


# =============================================================================
# VULNERABLE ENDPOINT — DO NOT USE IN PRODUCTION
# Vulnerability: OS Command Injection via shell=True
# The user-supplied `target` parameter is passed directly into a shell command
# without any sanitization. An attacker can inject shell metacharacters such as
# ; | && to chain arbitrary commands.
#
# Example exploit:
#   /ping?target=8.8.8.8; cat flag.txt
# =============================================================================
@app.route("/ping")
def ping():
    target = request.args.get("target", "")

    if not target:
        return render_template("tools.html", ping_result="Error: No target specified.")

    # VULNERABLE: shell=True with unsanitized user input
    try:
        result = subprocess.run(
            f"ping -c 1 {target}",   # <-- user input concatenated directly!
            shell=True,              # <-- shell=True enables metacharacter injection
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Error: Request timed out."
    except Exception as e:
        output = f"Error: {str(e)}"

    return render_template("tools.html", ping_result=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
