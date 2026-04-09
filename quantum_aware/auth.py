"""
auth.py — Authentication helpers for Quantum-Aware Enterprise.

Uses path-scoped signed cookies instead of Flask session so that admin and
user sessions are completely independent even in the same browser.

  user_auth  cookie  Path=/user   → only sent to /user/* requests
  admin_auth cookie  Path=/admin  → only sent to /admin/* requests
"""

import functools
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import request, abort, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db

# -----------------------------------------------------------------------
# Password helpers
# -----------------------------------------------------------------------

def hash_password(password: str) -> str:
    return generate_password_hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)

# -----------------------------------------------------------------------
# Signed token helpers  (uses the app secret key)
# Max age: 8 hours
# -----------------------------------------------------------------------

_MAX_AGE = 8 * 3600   # seconds

def _serializer():
    from flask import current_app
    return URLSafeTimedSerializer(current_app.secret_key, salt='qaware-auth')

def create_auth_token(user_id: int, role: str) -> str:
    """Return a signed token encoding user_id + role."""
    return _serializer().dumps({'user_id': user_id, 'role': role})

def decode_auth_token(token: str) -> dict | None:
    """Return the payload dict or None if invalid/expired."""
    try:
        return _serializer().loads(token, max_age=_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None

# -----------------------------------------------------------------------
# Cookie names & paths
# -----------------------------------------------------------------------

COOKIE_MAP = {
    'admin': {'name': 'admin_auth', 'path': '/admin'},
    'user':  {'name': 'user_auth',  'path': '/user'},
}

def _read_role_token(role: str) -> dict | None:
    """Read and validate the role-specific cookie from the current request."""
    cfg = COOKIE_MAP.get(role)
    if not cfg:
        return None
    raw = request.cookies.get(cfg['name'])
    if not raw:
        return None
    return decode_auth_token(raw)

# -----------------------------------------------------------------------
# Login / logout helpers
# -----------------------------------------------------------------------

def validate_credentials(email: str, password: str):
    """
    Check email/password against DB.
    Returns sqlite3.Row on success, None on failure.
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
        return None
    return user

# Keep old name for backward compat with app.py call site
def login_user(email: str, password: str) -> bool:
    """Kept for compatibility – call validate_credentials instead."""
    return validate_credentials(email, password) is not None

def logout_user():
    """No-op – cookies cleared in the logout route response."""
    pass

# -----------------------------------------------------------------------
# get_current_user
# -----------------------------------------------------------------------

def get_current_user():
    """
    Return the DB row for the currently authenticated user by reading
    whichever role cookie is present in this request.
    """
    for role in ('user', 'admin'):
        payload = _read_role_token(role)
        if payload:
            conn = get_db()
            try:
                return conn.execute(
                    "SELECT id, email, role, created_at FROM users WHERE id = ?",
                    (payload['user_id'],)
                ).fetchone()
            finally:
                conn.close()
    return None

def get_current_user_id() -> int | None:
    """Return just the user_id from the current request's auth cookie."""
    for role in ('user', 'admin'):
        payload = _read_role_token(role)
        if payload:
            return payload['user_id']
    return None

# -----------------------------------------------------------------------
# require_role decorator
# -----------------------------------------------------------------------

def require_role(role: str):
    """
    Decorator: abort(403) if the role-specific signed cookie is missing
    or invalid. Because cookies are path-scoped, admin and user sessions
    never collide even in the same browser.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            payload = _read_role_token(role)
            if payload is None or payload.get('role') != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator
