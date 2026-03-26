"""
app.py — Flask application entry point for Quantum-Aware Enterprise.

Responsibilities:
  - Create and configure the Flask app
  - Initialise the database (creates tables on first run)
  - Seed two default accounts if users table is empty
  - Register admin_routes and user_routes blueprints
  - Define core routes: /, /login (GET+POST), /logout
"""

import sys
import os
import threading
import time

# Make project root importable regardless of working directory
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, redirect, url_for, render_template, request, flash

import config
import database
import auth
import state_engine
from routes.admin_routes import admin_bp
from routes.user_routes import user_bp

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# ---------------------------------------------------------------------------
# Initialise database & seed accounts
# ---------------------------------------------------------------------------

def seed_accounts() -> None:
    """Insert default admin and user accounts if the users table is empty."""
    conn = database.get_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            seeds = [
                ('admin@qaware.com', auth.hash_password('admin123'), 'admin'),
                ('user@qaware.com',  auth.hash_password('user123'),  'user'),
            ]
            conn.executemany(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                seeds
            )
            conn.commit()
            print("[app] Seeded 2 default accounts (admin + user).")
    finally:
        conn.close()


with app.app_context():
    database.init_db()
    seed_accounts()

    # Edge case: resume rotation loops for files stuck in CONT_ROTATION
    import rotation_loop
    conn = database.get_db()
    try:
        stuck = conn.execute(
            "SELECT id FROM files WHERE encryption_state = 'CONT_ROTATION'"
        ).fetchall()
        for row in stuck:
            rotation_loop.start_loop(row['id'])
            print(f"[app] Resumed rotation loop for file_id={row['id']}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------

app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(user_bp,  url_prefix='/user')


# ---------------------------------------------------------------------------
# Core routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Landing page."""
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET  → render login form
    POST → validate credentials, redirect by role
    """
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        success = auth.login_user(email, password)

        if success:
            role = auth.get_current_user()['role']
            if role == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('user.files'))
        else:
            flash('Invalid email or password.', 'error')
            return render_template('login.html'), 401

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear session and redirect to login."""
    auth.logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Background monitor (evaluates all files every 10 seconds)
# ---------------------------------------------------------------------------

def _background_monitor():
    """Daemon thread: evaluate state transitions for every file, every 10s."""
    time.sleep(5)  # initial delay to let app fully start
    print("[monitor] Background threat monitor started (10s interval)")
    while True:
        try:
            with app.app_context():
                conn = database.get_db()
                try:
                    file_ids = [r['id'] for r in
                                conn.execute("SELECT id FROM files").fetchall()]
                finally:
                    conn.close()

                for fid in file_ids:
                    try:
                        state_engine.evaluate_and_transition(fid)
                    except Exception as e:
                        print(f"[monitor] Error evaluating file {fid}: {e}")
        except Exception as e:
            print(f"[monitor] Error: {e}")

        time.sleep(10)


# Start monitor only once (avoid double-start from Flask reloader)
_monitor_started = False

def _start_monitor_once():
    global _monitor_started
    if not _monitor_started:
        _monitor_started = True
        t = threading.Thread(target=_background_monitor, daemon=True,
                             name="threat-monitor")
        t.start()

with app.app_context():
    _start_monitor_once()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
