# QuantumShield — Adaptive Moving-Target Encryption

> **Quantum-Aware Enterprise Security Platform**  
> A Flask-based cloud file vault that fights back against cryptographic attacks in real time.

---

## What Is This?

QuantumShield is a 3-tier adaptive encryption system that continuously monitors access patterns using a custom ML classifier and autonomously shifts the encryption state of every stored file based on the current threat level.

Files are never just encrypted and forgotten. The system watches every login attempt, request rate, IP anomaly, and user-agent pattern — and silently escalates or de-escalates encryption strength in the background, without any manual intervention.

**The core idea**: If an attacker is trying to brute-force a key, QuantumShield continuously regenerates new ones — faster than any attack can keep up. This directly defeats both classical brute-force and Grover's algorithm (quantum-accelerated key search).

---

## The Three Encryption States

| State | Name | Algorithm | Trigger | Behavior |
|---|---|---|---|---|
| **S1** | Normal | AES-128-GCM | Baseline | Standard encryption at rest |
| **S2** | Suspicious | AES-256-GCM | ≥5 auth failures in 60s | Full re-encryption with 256-bit key |
| **S3** | Active Attack | AES-256 + Continuous Rotation | Sustained anomaly | Keys rotate every 4 seconds — evasion loop |

**Reversion uses hysteresis** to prevent oscillation:
- S3 → S2: Immediate when ML confirms attack has stopped
- S2 → S1: Only after **5 full minutes** of clean behaviour, with a final ML check before reverting

---

## Demo: Watch It Work (Quickest Path)

### Option A — Built-in Simulation (no setup needed)
1. Start the server and log in as **admin@qaware.com**
2. Go to **Dashboard** → click **⚡ SIMULATE ATTACK** in the demo panel
3. Watch the dashboard shift to red, evasion loop counter starts climbing
4. Click **■ STOP ATTACK** → observe the reversion through S3 → S2 → S1
5. Use **1× / 2× / 5×** speed selector to control how fast keys rotate

### Option B — Real Attack Script (live demo for judges)
Run the bundled `attack.py` from a second terminal while the server is running:

```bash
# Terminal 1 — start server
cd quantum_aware
python app.py

# Terminal 2 — launch real credential-stuffing attack
cd ..
python attack.py
```

`attack.py` spawns **5 parallel threads**, each firing 20 login attempts with wrong passwords against `http://127.0.0.1:5000/login`, using rotated User-Agent strings and a fixed spoofed IP (`X-Forwarded-For: 192.168.1.100`). This triggers real `AUTH_FAIL` entries in the database, which the ML engine detects within its 60-second sliding window — causing a genuine S1 → S2 transition visible live on the admin dashboard.

---

## Quick Start

### Prerequisites
- Python **3.11** (required — see `runtime.txt`)
- pip

### Install & Run

```bash
# 1. Clone
git clone https://github.com/alokkiid/quantum.git
cd quantum

# 2. Create virtual environment with Python 3.11
python3.11 -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
cd quantum_aware
python app.py
```

Server starts at **http://127.0.0.1:5000**

> **Windows note**: If your system Python is not 3.11, install it separately and use:
> `py -3.11 -m venv venv`

---

## Default Accounts

| Role | Email | Password |
|---|---|---|
| Admin | admin@qaware.com | admin123 |
| User | *(self-register at `/register`)* | *(your choice)* |

The admin account is seeded automatically on first run. Users register themselves at `/register`.

---

## Running the Real Attack (Judges Demo)

```bash
python attack.py
```

**What it does:**
- 5 concurrent threads × 20 attempts = **100 failed login requests**
- Randomizes `User-Agent` across 5 browser signatures per request
- Pins `X-Forwarded-For` to `192.168.1.100` to simulate a single persistent attacker
- Each failed attempt writes a real `AUTH_FAIL` row to `access_logs`
- The ML engine's 60-second sliding window detects the spike in `auth_failure_rate` and `ip_auth_failures`
- Within one monitor cycle (≤10 seconds), the state transitions: **AES-128 → AES-256**
- If the attack intensity is high enough, continues escalating to **CONT_ROTATION**

Watch the effect live on the admin dashboard at `/admin/dashboard`.

---

## Running Integration Tests

```bash
python test_integration.py
```

Covers 12 scenarios end-to-end: login → upload → encrypt → attack injection → state escalation → rotation → stop → decrypt → download → reset → CSV export → re-login.

---

## Project Structure

```
quantum/
├── attack.py                    ← Real attack script (credential stuffing, 5 threads)
├── test_integration.py          ← 12-case integration test suite
├── requirements.txt
└── quantum_aware/
    ├── app.py                   ← Flask entry point, request tracking, background monitor
    ├── auth.py                  ← Path-scoped signed cookies, @require_role, hashing
    ├── config.py                ← All runtime constants (thresholds, intervals, paths)
    ├── database.py              ← SQLite init, 5-table schema, get_db()
    ├── crypto_engine.py         ← AES-GCM encrypt/decrypt/rotate, vault I/O
    ├── ml_engine.py             ← 7-feature threat classifier, security score
    ├── state_engine.py          ← S1↔S2↔S3 state machine, hysteresis timers
    ├── rotation_loop.py         ← Daemon thread evasion loop (State 3)
    ├── routes/
    │   ├── admin_routes.py      ← Admin dashboard, API, simulate/isolate endpoints
    │   └── user_routes.py       ← Upload, download, delete, file listing
    ├── templates/
    │   ├── base.html            ← Glassmorphism layout shell
    │   ├── landing.html
    │   ├── login.html
    │   ├── register.html
    │   ├── admin/
    │   │   ├── dashboard.html   ← Live threat monitor, evasion loop counter
    │   │   ├── files.html       ← File state matrix (all users)
    │   │   ├── threat.html      ← ML confidence scores, feature breakdown
    │   │   └── topology.html    ← Crypto key topology viewer
    │   └── user/
    │       ├── files.html       ← User file manager (cache-busted, no-store)
    │       └── upload.html
    ├── static/                  ← CSS, JS assets
    ├── vault/                   ← Encrypted .enc files stored here
    ├── requirements.txt
    └── runtime.txt              ← python-3.11.0
```

---

## Architecture

### Request Tracking (`app.py`)
Every HTTP request is timestamped in-memory via `before_request`. Three deques maintain a 60-second rolling window: `_global_timestamps`, `_ip_timestamps[ip]`, and `_ip_auth_failures[ip]`. Auth failures also write real `AUTH_FAIL` records to `access_logs` so the ML engine can read them from the database. The `get_request_metrics(ip)` function is called by the ML engine on every evaluation cycle.

### ML Engine (`ml_engine.py`)
Extracts a **7-feature vector** on demand:

| # | Feature | Source |
|---|---|---|
| 0 | `global_rps` | In-memory deque (all requests / 60s) |
| 1 | `ip_rps` | In-memory deque (per-IP requests / 60s) |
| 2 | `ip_auth_failures` | In-memory deque (per-IP auth fails in 60s) |
| 3 | `auth_failure_rate` | DB: AUTH_FAIL / total events in 60s window |
| 4 | `geo_anomaly_score` | DB: unique IPs / total events |
| 5 | `time_of_day_score` | UTC hour (0.8 if 22:00–06:00, else 0.2) |
| 6 | `user_agent_entropy` | DB: unique User-Agents / total events |

Classification uses **sigmoid-interpolated confidence scores** (not hard thresholds) giving a continuous probability distribution across Normal / Suspicious / Attack. The dominant probability determines the state label. A hard override kicks in when `ip_auth_failures ≥ 5` — this ensures `attack.py` reliably triggers S2.

### Cryptographic State Machine (`state_engine.py`)

```
         ≥5 AUTH_FAIL in 60s             sustained high confidence
  S1 ─────────────────────────► S2 ──────────────────────────────► S3
(AES-128-GCM)             (AES-256-GCM)                    (CONT_ROTATION)
      ◄──────────────────────────── ◄──────── ML clears ────────────
        S2→S1 after 5-min hysteresis     S3→S2 immediate
```

All transitions call `crypto_engine.rotate_key()` to perform a real full re-encryption — not just a metadata update.

### Continuous Rotation Loop (`rotation_loop.py`)
In State 3, one daemon thread per file runs `_loop_worker()`. Every `ROTATION_INTERVAL_SECONDS` (default 4s):
1. Calls `crypto_engine.rotate_key(file_id, new_bits=256)`
2. Logs a `ROTATION` event to `audit_trail` with an incrementing `rotation_count`
3. Re-evaluates ML. If threat has cleared, calls `state_engine.transition_attack_to_suspicious()` and exits

The loop can be sped up for demos via `POST /api/config/rotation-speed` (1×/2×/5× multiplier).

### Key Rotation Cycle (`crypto_engine.py`)
The `rotate_key()` function is a **full atomic re-encryption** — 12 steps:

1. Fetch current `ACTIVE` key from `encryption_keys`
2. Read `.enc` ciphertext from `vault/`
3. Decrypt in memory with AES-GCM (auth tag validated)
4. Generate new key — `os.urandom(32)` for AES-256
5. Generate fresh 12-byte nonce — `os.urandom(12)`
6. Re-encrypt plaintext with new key + new nonce
7. Overwrite vault file atomically
8. Mark old key `DESTROYED` (timestamp recorded)
9. Insert new key as `ACTIVE`
10. Update `files.current_key_id`
11. Audit: `KEY_DESTROYED` event for old key
12. Audit: `KEY_GENERATED` event for new key

### Authentication (`auth.py`)
Uses **path-scoped signed cookies** via `itsdangerous.URLSafeTimedSerializer`. The `admin_auth` cookie is scoped to `/admin` and the `user_auth` cookie to `/user` — they never collide even in the same browser tab. 8-hour expiry. The `@require_role('admin')` decorator reads and validates the cookie; if missing or expired it calls `abort(403)`, which redirects to login.

---

## Database Schema (SQLite)

| Table | Key Columns | Purpose |
|---|---|---|
| `users` | `id`, `email`, `password_hash`, `role` | Accounts |
| `files` | `id`, `user_id`, `stored_name`, `encryption_state`, `current_key_id` | File metadata |
| `encryption_keys` | `id`, `file_id`, `key_data` (BLOB), `nonce`, `algorithm`, `status` | Key lifecycle |
| `access_logs` | `id`, `file_id`, `source_ip`, `event_type`, `user_agent`, `timestamp` | Per-request events |
| `audit_trail` | `id`, `file_id`, `event_type`, `old_state`, `new_state`, `key_id`, `rotation_count` | Full audit log |

---

## API Reference

### Public

| Method | Path | Description |
|---|---|---|
| GET | `/` | Landing page |
| GET | `/register` | Registration form |
| POST | `/register` | Create user account |
| GET | `/login` | Login page |
| POST | `/login` | Authenticate → set role cookie |
| GET | `/logout` | Clear cookies, redirect to login |

### User Routes (`/user`)

| Method | Path | Description |
|---|---|---|
| GET | `/files` | File manager page (Cache-Control: no-store) |
| GET | `/upload` | Upload form |
| POST | `/upload` | Encrypt and store file → `{success, file_id}` |
| GET | `/files/data` | JSON: current user's file list |
| GET | `/download/<id>` | Decrypt and stream file |
| POST | `/delete/<id>` | Remove from vault and DB → `{success: true}` |

### Admin Routes (`/admin`)

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard` | Live threat monitor dashboard |
| GET | `/files` | All-user file state matrix |
| GET | `/threat` | ML confidence scores + feature breakdown |
| GET | `/topology` | Crypto key topology viewer |
| GET | `/files/data` | JSON: all files from all users |
| POST | `/rotate/<id>` | Force key rotation to AES-256 |
| GET | `/api/status` | Live system threat status JSON |
| POST | `/api/simulate/attack` | Inject synthetic attack events |
| POST | `/api/simulate/stop` | Stop simulation |
| POST | `/api/simulate/reset` | Reset all states, clear logs |
| POST | `/api/config/rotation-speed` | Set rotation multiplier (1×/2×/5×) |
| POST | `/api/isolate/<id>` | Force file to CONT_ROTATION |
| GET | `/api/logs/export` | Download audit trail as CSV |

---

## Configuration (`config.py`)

| Constant | Default | Description |
|---|---|---|
| `ROTATION_INTERVAL_SECONDS` | `4` | Key rotation interval in State 3 |
| `HYSTERESIS_MINUTES` | `5` | Clean window required before S2→S1 |
| `ATTACK_THRESHOLD_RPS` | `100` | RPS threshold to confirm Active Attack |
| `SUSPICIOUS_THRESHOLD_FAILURES` | `5` | Auth failures to trigger S1→S2 |
| `VAULT_PATH` | `vault/` | Encrypted file storage directory |
| `DATABASE_PATH` | `quantum_aware.db` | SQLite database file |
| `SECRET_KEY` | `qaware-dev-secret-2026` | Flask signing key *(change for production)* |

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Web Framework | Flask | 3.1.3 |
| Cryptography | `cryptography` (AES-GCM via AESGCM) | 46.0.6 |
| ML / Numerics | scikit-learn + NumPy | 1.8.0 / 2.4.3 |
| Auth tokens | itsdangerous URLSafeTimedSerializer | 2.2.0 |
| Password hashing | Werkzeug PBKDF2-SHA256 | 3.1.7 |
| Database | SQLite 3 (built-in) | — |
| Concurrency | Python `threading` (daemon threads + Events) | — |
| Templating | Jinja2 (glassmorphism dark UI) | 3.1.6 |
| Python | CPython | 3.11 |

---

## Security Notes

- All files are AES-GCM encrypted before touching disk — plaintext never persists in `vault/`
- Keys are stored as BLOBs in SQLite with status tracking; `DESTROYED` keys are retained for audit completeness, not deleted
- GCM authentication tags are validated on every decrypt — tampered ciphertext raises `ValueError`
- `SECRET_KEY` in `config.py` is a dev placeholder — replace with `secrets.token_hex(32)` before any real deployment
- `X-Forwarded-For` is trusted for IP extraction (appropriate for localhost demo; configure proxy trust for production)
- Auth cookies are `HttpOnly`, `SameSite=Lax`, path-scoped — CSRF and cross-role session leakage are mitigated by design

---

## Author

Built by [@alokkiid](https://github.com/alokkiid) — QuantumShield, 2026.
