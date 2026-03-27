"""
WARNING: This application is intentionally vulnerable.
It is designed for security scanning and educational purposes ONLY.
DO NOT deploy to production.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, render_template, g

app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), "users.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def setup():
    """Create the database and seed a test user."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    # Seed admin user (plain-text password — intentionally insecure)
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO users (username, password) VALUES ('admin', 'password123')"
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# --- SQL Injection -----------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    result = None
    query = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILITY: string-formatted query — SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        db = get_db()
        try:
            rows = db.execute(query).fetchall()
            if rows:
                result = f"Login successful! Welcome, {rows[0]['username']}."
            else:
                result = "Invalid credentials."
        except Exception as e:
            result = f"Database error: {e}"

    return render_template("login.html", result=result, query=query)


# --- Reflected XSS -----------------------------------------------------------
@app.route("/search")
def search():
    term = request.args.get("q", "")

    # VULNERABILITY: user input rendered directly — reflected XSS
    results_html = f"<p>You searched for: <strong>{term}</strong></p>"

    return render_template("search.html", results_html=results_html, term=term)


# --- OS Command Injection -----------------------------------------------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None

    if request.method == "POST":
        host = request.form.get("host", "")

        # VULNERABILITY: unsanitised input passed to shell — command injection
        try:
            output = subprocess.check_output(
                f"ping -c 2 {host}",
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=10,
            ).decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            output = "Error: command timed out."
        except subprocess.CalledProcessError as e:
            output = e.output.decode("utf-8", errors="replace")
        except Exception as e:
            output = f"Error: {e}"

    return render_template("ping.html", output=output)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup()
    app.run(debug=True, port=5000)
