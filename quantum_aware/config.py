"""
config.py — Application configuration constants for Quantum-Aware Enterprise.
"""

from datetime import timedelta

# Flask secret key for session signing
SECRET_KEY = 'qaware-dev-secret-2026'

# SQLite database file path (relative to project root)
DATABASE_PATH = 'quantum_aware.db'

# Directory where encrypted files (.enc) are stored
VAULT_PATH = 'vault/'

# Active Attack: key rotation interval in seconds
ROTATION_INTERVAL_SECONDS = 4

# Hysteresis: minutes of clean behaviour before S2 → S1 reversion
HYSTERESIS_MINUTES = 5

# Threshold: requests/sec that confirms an active attack (S2 → S3)
ATTACK_THRESHOLD_RPS = 100

# Threshold: auth failures in 60-second window that trigger S1 → S2
SUSPICIOUS_THRESHOLD_FAILURES = 5

# ---------------------------------------------------------------------------
# Session configuration
# ---------------------------------------------------------------------------

# Make sessions permanent so they survive page refreshes and tab switches
SESSION_PERMANENT = True

# How long a session lasts before the user must log in again
PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

# Prevent JavaScript from reading the session cookie
SESSION_COOKIE_HTTPONLY = True

# Allow cookie on same-site navigations (safe for localhost)
SESSION_COOKIE_SAMESITE = 'Lax'

# ---------------------------------------------------------------------------
# Server-side session (flask-session)
# Stores session data as files on disk instead of in the browser cookie.
# Each browser tab gets its own session file, so admin and user sessions
# are completely independent even in the same browser.
# ---------------------------------------------------------------------------
SESSION_TYPE = 'filesystem'          # store sessions as files in flask_session/
SESSION_FILE_DIR = 'flask_session'  # relative to the CWD (quantum_aware/)
SESSION_USE_SIGNER = True           # sign the session ID cookie
SESSION_FILE_THRESHOLD = 500        # max files before old ones are cleaned up
