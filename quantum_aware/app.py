"""
app.py — Flask application entry point for Quantum-Aware Enterprise.
"""

import sys
import os
import threading
import time
from collections import defaultdict, deque

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
# Real-time traffic tracking (Fix 2 + Fix 3)
# ---------------------------------------------------------------------------

_req_lock = threading.Lock()
_global_timestamps: deque = deque()
_ip_timestamps: dict = defaultdict(deque)
_ip_auth_failures: dict = defaultdict(deque)


def _purge_window(q: deque, now: float, window: int = 60) -> None:
    while q and now - q[0] > window:
        q.popleft()


@app.before_request
def track_all_requests():
    now = time.time()
    ip = request.remote_addr or '0.0.0.0'
    with _req_lock:
        _global_timestamps.append(now)
        _purge_window(_global_timestamps, now)
        q = _ip_timestamps[ip]
        q.append(now)
        _purge_window(q, now)


def record_auth_failure(ip: str) -> None:
    now = time.time()
    with _req_lock:
        q = _ip_auth_failures[ip]
        q.append(now)
        _purge_window(q, now)


def get_request_metrics(ip: str = None) -> dict:
    now = time.time()
    with _req_lock:
        _purge_window(_global_timestamps, now)
        global_rps = len(_global_timestamps) / 60.0
        ip_rps = 0.0
        ip_fails = 0
        if ip:
            q = _ip_timestamps.get(ip)
            if q:
                _purge_window(q, now)
                ip_rps = len(q) / 60.0
            fq = _ip_auth_failures.get(ip)
            if fq:
                _purge_window(fq, now)
                ip_fails = len(fq)
    return {
        'global_rps': global_rps,
        'ip_rps': ip_rps,
        'ip_auth_failures': ip_fails,
    }


# ---------------------------------------------------------------------------
# Initialise database & seed accounts
# ---------------------------------------------------------------------------

def seed_accounts() -> None:
    """Insert only admin account on first run. Users register themselves."""
    conn = database.get_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            seeds = [
                ('admin@qaware.com', auth.hash_password('admin123'), 'admin'),
            ]
            conn.executemany(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                seeds
            )
            conn.commit()
            print("[app] Seeded admin account.")
    finally:
        conn.close()


with app.app_context():
    database.init_db()
    seed_accounts()

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
    return render_template('landing.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('register.html'), 400

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html'), 400

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html'), 400

        conn = database.get_db()
        try:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing:
                flash('An account with this email already exists.', 'error')
                return render_template('register.html'), 400

            conn.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'user')",
                (email, auth.hash_password(password))
            )
            conn.commit()
        finally:
            conn.close()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
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
            record_auth_failure(request.remote_addr or '0.0.0.0')
            flash('Invalid email or password.', 'error')
            return render_template('login.html'), 401

    return render_template('login.html')


@app.route('/logout')
def logout():
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
# Background monitor
# ---------------------------------------------------------------------------

def _background_monitor():
    time.sleep(5)
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