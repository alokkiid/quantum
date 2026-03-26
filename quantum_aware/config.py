"""
config.py — Application configuration constants for Quantum-Aware Enterprise.
"""

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
