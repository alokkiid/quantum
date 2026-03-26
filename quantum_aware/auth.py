"""
auth.py — Authentication helpers for Quantum-Aware Enterprise.

Public API:
  hash_password(password)           → hashed string
  verify_password(password, hash)   → bool
  login_user(email, password)       → True | False  (also sets session)
  logout_user()                     → None
  require_role(role)                → decorator (403 if wrong role)
  get_current_user()                → sqlite3.Row | None
"""

import functools
from flask import session, abort, request
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a Werkzeug-generated password hash (pbkdf2:sha256)."""
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return True if *password* matches *password_hash*."""
    return check_password_hash(password_hash, password)


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def login_user(email: str, password: str) -> bool:
    """
    Validate credentials and populate the Flask session.

    Sets:
      session['user_id']  → int
      session['role']     → 'admin' | 'user'

    Returns True on success, False on bad credentials.
    """
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT id, password_hash, role FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    finally:
        conn.close()

    if user is None or not verify_password(password, user['password_hash']):
        return False

    session.clear()
    session['user_id'] = user['id']
    session['role'] = user['role']
    return True


def logout_user() -> None:
    """Clear the current Flask session (logs the user out)."""
    session.clear()


# ---------------------------------------------------------------------------
# Current user helper
# ---------------------------------------------------------------------------

def get_current_user():
    """
    Return the full user row from DB for the session user, or None if
    the session is unauthenticated.
    """
    user_id = session.get('user_id')
    if user_id is None:
        return None

    conn = get_db()
    try:
        user = conn.execute(
            "SELECT id, email, role, created_at FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    finally:
        conn.close()

    return user


# ---------------------------------------------------------------------------
# Role guard decorator
# ---------------------------------------------------------------------------

def require_role(role: str):
    """
    Decorator factory.  Wrap any route with @require_role('admin') or
    @require_role('user') to enforce access control.

    Returns HTTP 403 Forbidden if:
      - User is not logged in, OR
      - User's role does not match *role*
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            current_role = session.get('role')
            if current_role is None or current_role != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator
