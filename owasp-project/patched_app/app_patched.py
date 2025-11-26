from flask import Flask, request, render_template, redirect
from flask_wtf import CSRFProtect
import sqlite3, os, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
csrf = CSRFProtect(app)

DB = os.path.join(os.path.dirname(__file__), "data.db")


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            bio TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            user TEXT,
            comment TEXT
        )
    """)

    c.execute("INSERT OR IGNORE INTO users (id, name, bio) VALUES (1, 'Alice', 'Hello')")
    c.execute("INSERT OR IGNORE INTO users (id, name, bio) VALUES (2, 'Bob', 'Hi')")

    conn.commit()
    conn.close()


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com"
    return response


@app.route("/")
def index():
    return render_template("index.html")


# Secure SQL Query (Parameterized)
@app.route("/search")
def search():
    q = request.args.get("q", "")
    param = f"%{q}%"

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, name, bio FROM users WHERE name LIKE ?", (param,))
    results = c.fetchall()
    conn.close()

    return render_template("search.html", q=q, results=results)


# Secure XSS (autoescaping enabled)
@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "POST":
        user = request.form.get("user", "anon")
        msg = request.form.get("comment", "")

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO comments (user, comment) VALUES (?, ?)", (user, msg))
        conn.commit()
        conn.close()

        return redirect("/comment")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT user, comment FROM comments ORDER BY id DESC LIMIT 20")
    comments = c.fetchall()
    conn.close()

    return render_template("comment.html", comments=comments)


# CSRF-Protected Profile Update
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if request.method == "POST":
        bio = request.form.get("bio", "")

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("UPDATE users SET bio=? WHERE id=1", (bio,))
        conn.commit()
        conn.close()

        return "Profile updated (secured)."

    return render_template("profile.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
