# OWASP Web App Security Audit - Lab Project

Folders:
- vuln_app: intentionally vulnerable Flask app
- patched_app: fixed version demonstrating mitigations
- exploits: PoC scripts and pages

## Setup
1. Create virtualenv and activate
2. pip install flask flask-wtf requests
3. Run vulnerable app:
   - cd vuln_app
   - python app_vuln.py
4. Visit http://127.0.0.1:5000

## Tests
- SQLi: http://127.0.0.1:5000/search?q=' OR '1'='1
- XSS: post &lt;script&gt;alert('XSS')&lt;/script&gt; in comments
- CSRF: open exploits/csrf_poc.html while app is running

## Notes
- Use patched_app to show fixes.
- Evidence: screenshots, curl logs, sqlite3 queries, exploit outputs.
- Ethical use only: do not attack systems you don't own or have permission to test.
