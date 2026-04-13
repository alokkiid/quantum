# Quantum-Aware Enterprise

**GitHub Repository:** https://github.com/alokkiid/quantum


**Adaptive Moving-Target Encryption for Cloud File Storage**

## What it does

Quantum-Aware Enterprise is a Flask-based cloud storage platform that employs **adaptive moving-target defense** against cryptographic attacks. Files uploaded by users are encrypted with AES-128-GCM at rest. A background ML-powered threat monitor continuously evaluates access patterns (auth failures, IP diversity, request rates) and dynamically shifts the system through three escalating encryption states.

The three tiers operate as a state machine: **State 1 (Normal / AES-128)** is the baseline, where files are encrypted with standard 128-bit keys. When anomalous access patterns are detected, the system escalates to **State 2 (Suspicious / AES-256)**, performing a full re-encryption cycle with 256-bit keys and tighter monitoring. If a sustained attack is confirmed, it activates **State 3 (Active Attack / Continuous Rotation)**, engaging an evasion loop that re-encrypts all targeted files with fresh AES-256 keys every few seconds — making it impossible for an attacker to maintain a decryption window. When the threat subsides, the system gracefully steps down through states with hysteresis timers to prevent oscillation.

## Setup

```bash
cd quantum_aware
pip install flask cryptography scikit-learn numpy werkzeug apscheduler
.\venv\Scripts\python.exe quantum_aware\app.py (if python 14 is installed in laptop then download python 11 in virtual environment)
```

The server starts at **http://127.0.0.1:5000**

## Default Accounts

| Role  | Email               | Password   |
|-------|---------------------|------------|
| Admin | admin@qaware.com    | admin123   |
| User  | user@qaware.com     | user123    |

## Demo (quickest way to see the system work)

1. Login as **user@qaware.com** → Upload any file (it gets AES-128 encrypted)
2. Login as **admin@qaware.com** → Open the Dashboard
3. Click **⚡ SIMULATE ATTACK** in the demo controls panel (bottom-right)
4. Watch the dashboard shift to **red**, evasion loop counter starts incrementing
5. Click **■ STOP ATTACK** → Watch it revert through Suspicious → Normal
6. Click **↻ RESET ALL STATES** to return everything to clean AES-128

Use the **1×/2×/5×** speed selector to change how fast keys rotate during an attack.

## API Reference

### Public Routes

| Method | Path       | Auth | Description             |
|--------|------------|------|-------------------------|
| GET    | `/`        | No   | Landing page            |
| GET    | `/login`   | No   | Login page              |
| POST   | `/login`   | No   | Authenticate user       |
| GET    | `/logout`  | No   | Clear session           |

### User Routes (prefix: `/user`)

| Method | Path              | Auth | Description                      | Request Body                | Response                |
|--------|-------------------|------|----------------------------------|-----------------------------|-------------------------|
| GET    | `/files`          | User | File manager page                | —                           | HTML                    |
| GET    | `/upload`         | User | Upload page                      | —                           | HTML                    |
| GET    | `/files/data`     | User | JSON list of user's files        | —                           | `[{id, name, size, …}]` |
| POST   | `/upload`         | User | Upload & encrypt file            | `multipart/form-data` file  | `{success, file_id, …}` |
| GET    | `/download/<id>`  | User | Download & decrypt file          | —                           | File bytes              |
| POST   | `/delete/<id>`    | User | Delete file from vault           | —                           | `{success: true}`       |

### Admin Routes (prefix: `/admin`)

| Method | Path                          | Auth  | Description                        | Request Body                            | Response                     |
|--------|-------------------------------|-------|------------------------------------|-----------------------------------------|------------------------------|
| GET    | `/dashboard`                  | Admin | Dashboard page                     | —                                       | HTML                         |
| GET    | `/files`                      | Admin | File matrix page                   | —                                       | HTML                         |
| GET    | `/threat`                     | Admin | Threat intelligence page           | —                                       | HTML                         |
| GET    | `/topology`                   | Admin | Crypto topology page               | —                                       | HTML                         |
| GET    | `/files/data`                 | Admin | JSON of all files (all users)      | —                                       | `[{id, name, state, …}]`     |
| POST   | `/rotate/<id>`                | Admin | Force-rotate a file to AES-256     | —                                       | `{success, new_key_id}`      |
| GET    | `/api/status`                 | Admin | Live system threat status          | —                                       | `{global_threat_level, …}`   |
| POST   | `/api/simulate/attack`        | Admin | Inject attack events               | `{file_id, intensity}`                  | `{success, state}`           |
| POST   | `/api/simulate/stop`          | Admin | Stop attack simulation             | `{file_id}`                             | `{success: true}`            |
| POST   | `/api/simulate/reset`         | Admin | Reset all states, clear logs       | —                                       | `{success: true}`            |
| POST   | `/api/config/rotation-speed`  | Admin | Change rotation interval           | `{multiplier: 1\|2\|5}`                 | `{success, interval}`        |
| POST   | `/api/isolate/<id>`           | Admin | Force file to CONT_ROTATION        | —                                       | `{success: true}`            |
| GET    | `/api/logs/export`            | Admin | Download audit trail as CSV        | —                                       | `audit_log.csv`              |

## Architecture

```
quantum_aware/
├── app.py              Flask entry point, route registration, startup recovery
├── config.py           Runtime configuration constants
├── auth.py             Session auth, password hashing, @require_role decorator
├── database.py         SQLite schema (5 tables), connection helper
├── crypto_engine.py    AES-GCM encrypt/decrypt/rotate, vault I/O
├── ml_engine.py        Threat classification (Normal/Suspicious/Attack)
├── state_engine.py     S1↔S2↔S3 state machine with hysteresis
├── rotation_loop.py    Daemon-thread evasion loop for State 3
├── routes/
│   ├── admin_routes.py Admin API + view routes
│   └── user_routes.py  User file management routes
├── templates/          8 Jinja2 templates (glassmorphism design system)
└── vault/              Encrypted .enc file storage
```

### Key Components

- **crypto_engine.py** — Handles all AES-GCM operations. `rotate_key()` performs a full decrypt→re-encrypt→swap-key cycle atomically within a single DB transaction.
- **ml_engine.py** — Analyzes access_logs to classify threat state using auth failure rates, IP diversity, and request frequency over a 60-second sliding window.
- **state_engine.py** — Manages the encryption state machine (S1→S2→S3) with configurable thresholds and hysteresis timers to prevent state oscillation.
- **rotation_loop.py** — Spawns a daemon thread per file in State 3, rotating keys every N seconds. Automatically re-evaluates ML after each cycle and steps down when the threat passes.

## Running Tests

```bash
python test_integration.py
```

Runs 12 integration tests covering the complete lifecycle: login → upload → attack → rotation → stop → download → reset → CSV export.
