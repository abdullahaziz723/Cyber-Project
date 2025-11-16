from flask import Flask, request, render_template, redirect
import sqlite3
import os

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), 'data.db')

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, bio TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (id, name, bio) VALUES (1, 'Alice', 'Hello')")
    c.execute("INSERT OR IGNORE INTO users (id, name, bio) VALUES (2, 'Bob', 'Hi')")
    c.execute('''CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, user TEXT, comment TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABLE SQLi: building SQL with string formatting (do NOT do this in real code)
@app.route('/search')
def search():
    q = request.args.get('q', '')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    query = "SELECT id, name, bio FROM users WHERE name LIKE '%{}%'".format(q)
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        results = [("error", str(e), "")]
    conn.close()
    return render_template('search.html', q=q, results=results)

# Stored XSS: comment is stored and rendered unsafely
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user = request.form.get('user', 'anon')
        comment = request.form.get('comment', '')
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO comments (user, comment) VALUES (?,?)", (user, comment))
        conn.commit()
        conn.close()
        return redirect('/comment')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT user, comment FROM comments ORDER BY id DESC LIMIT 20')
    comments = c.fetchall()
    conn.close()
    return render_template('comment.html', comments=comments)

# Simple profile change endpoint (no CSRF protection)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('UPDATE users SET bio=? WHERE id=1', (bio,))
        conn.commit()
        conn.close()
        return 'Profile updated for demo (vulnerable app)'
    return "<form method='POST'><input name='name' placeholder='name'><br><textarea name='bio' placeholder='bio'></textarea><br><button>Save</button></form>"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
