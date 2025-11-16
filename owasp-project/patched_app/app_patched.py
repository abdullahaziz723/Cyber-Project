from flask import Flask, request, render_template, redirect, session
from flask_wtf import CSRFProtect
import sqlite3, os, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
csrf = CSRFProtect(app)

DB = os.path.join(os.path.dirname(__file__), 'data.db')  # can reuse same db file or copy from vuln_app

def init_db():
    # Create DB if not exists (safe usage)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, bio TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (id, name, bio) VALUES (1, 'Alice', 'Hello')")
    c.execute("INSERT OR IGNORE INTO users (id, name, bio) VALUES (2, 'Bob', 'Hi')")
    c.execute('''CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, user TEXT, comment TEXT)''')
    conn.commit()
    conn.close()

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    # Simple CSP — adjust for your needs
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response

@app.route('/')
def index():
    return render_template('index.html')

# Safe parameterized query to prevent SQLi
@app.route('/search')
def search():
    q = request.args.get('q', '')
    param = f"%{q}%"
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT id, name, bio FROM users WHERE name LIKE ?', (param,))
    results = c.fetchall()
    conn.close()
    return render_template('search.html', q=q, results=results)

# Save comments, but do NOT render them with |safe - let template autoescape
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user = request.form.get('user', 'anon')
        comment = request.form.get('comment', '')
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('INSERT INTO comments (user, comment) VALUES (?,?)', (user, comment))
        conn.commit()
        conn.close()
        return redirect('/comment')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT user, comment FROM comments ORDER BY id DESC LIMIT 20')
    comments = c.fetchall()
    conn.close()
    return render_template('comment.html', comments=comments)

# Profile endpoint protected by CSRF (via flask-wtf)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        name = request.form.get('name')
        bio = request.form.get('bio', '')
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('UPDATE users SET bio=? WHERE id=1', (bio,))
        conn.commit()
        conn.close()
        return 'Profile updated (patched app)'
    # render a small HTML form that includes CSRF token
    return render_template('profile.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
