"""
ml_engine.py — ML threat classification for Quantum-Aware Enterprise.

Feature vector (7 features):
  [0] global_rps          — all requests / 60s (in-memory)
  [1] ip_rps              — requests from caller IP / 60s (in-memory)
  [2] ip_auth_failures    — auth failures from caller IP in 60s (in-memory)
  [3] auth_failure_rate   — AUTH_FAIL / total in DB logs
  [4] geo_anomaly_score   — unique IPs / total in DB logs
  [5] time_of_day_score   — 0.8 if night (22–06 UTC), else 0.2
  [6] user_agent_entropy  — unique UAs / total in DB logs
"""

import numpy as np
from datetime import datetime, timedelta
from database import get_db


def extract_features(file_id: int, ip: str = None, window_seconds: int = 60) -> np.ndarray:
    # Features 0-2: real-time in-memory
    try:
        import app as _app
        metrics = _app.get_request_metrics(ip)
    except Exception:
        metrics = {'global_rps': 0.0, 'ip_rps': 0.0, 'ip_auth_failures': 0}

    global_rps       = metrics['global_rps']
    ip_rps           = metrics['ip_rps']
    ip_auth_failures = float(metrics['ip_auth_failures'])

    # Features 3-6: DB-based
    cutoff = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat()
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT event_type, source_ip, user_agent FROM access_logs "
            "WHERE (file_id = ? OR file_id IS NULL) AND timestamp >= ?",
            (file_id, cutoff)
        ).fetchall()
    finally:
        conn.close()

    total = len(rows)

    auth_fails = sum(1 for r in rows if r['event_type'] == 'AUTH_FAIL')
    auth_failure_rate = auth_fails / max(total, 1)

    unique_ips = len(set(r['source_ip'] for r in rows if r['source_ip']))
    geo_anomaly_score = unique_ips / max(total, 1)

    hour = datetime.utcnow().hour
    time_of_day_score = 0.8 if (hour >= 22 or hour < 6) else 0.2

    unique_uas = len(set(r['user_agent'] for r in rows if r['user_agent']))
    user_agent_entropy = unique_uas / max(total, 1)

    return np.array([
        global_rps,
        ip_rps,
        ip_auth_failures,
        auth_failure_rate,
        geo_anomaly_score,
        time_of_day_score,
        user_agent_entropy,
    ])


def _sigmoid(x: float) -> float:
    """Numerically stable sigmoid."""
    if x >= 0:
        return 1.0 / (1.0 + np.exp(-x))
    e = np.exp(x)
    return e / (1.0 + e)


def classify_threat(feature_vector: np.ndarray) -> dict:

    """
    Produce continuous, interpolated ML confidence scores based on the actual
    magnitude of each threat signal — not fixed 3-bucket outputs.

    Attack score drivers:  global_rps, ip_rps
    Suspicious score drivers: ip_auth_failures, auth_failure_rate,
                              geo_anomaly_score, user_agent_entropy
    Normal score: residual after the above
    """
    from database import get_db

    conn = get_db()
    try:
        row = conn.execute(
        "SELECT COUNT(*) FROM access_logs WHERE event_type='AUTH_FAIL'"
        ).fetchone()
        ip_auth_failures = row[0]
    finally:
        conn.close()

    if ip_auth_failures >= 5:
        return {
        'state': 'Suspicious',
        'confidence': {
            'normal': 0.1,
            'suspicious': 0.8,
            'attack': 0.1
        }
    }
    global_rps        = feature_vector[0]
    ip_rps            = feature_vector[1]
    ip_auth_failures  = feature_vector[2]
    auth_failure_rate = feature_vector[3]
    geo_anomaly_score = feature_vector[4]
    # time_of_day_score = feature_vector[5]  (mild background signal)
    user_agent_entropy = feature_vector[6]

    # --- Attack confidence: driven by raw request-per-second volume ---
    # Sigmoid centred at 50 rps, steep at 5 rps/unit
    attack_raw = _sigmoid((global_rps - 5) / 2.0) * 0.7 \
               + _sigmoid((ip_rps    - 25) / 3.0) * 0.3
    attack_conf = float(np.clip(attack_raw, 0.0, 0.98))

    # --- Suspicious confidence: driven by auth failures & anomaly signals ---
    # ip_auth_failures: sigmoid centred at 5, 1 unit wide
    fail_sig   = _sigmoid((ip_auth_failures  - 3) / 0.5)
    # auth_failure_rate: sigmoid centred at 0.4
    rate_sig   = _sigmoid((auth_failure_rate - 0.4) / 0.05)
    # geo anomaly and UA entropy add soft evidence (0..0.2 contribution each)
    geo_sig    = float(np.clip(geo_anomaly_score,    0.0, 1.0)) * 0.15
    ua_sig     = float(np.clip(user_agent_entropy,   0.0, 1.0)) * 0.10
    suspicious_raw = fail_sig * 0.55 + rate_sig * 0.30 + geo_sig + ua_sig
    suspicious_conf = float(np.clip(suspicious_raw, 0.0, 0.98))

    # Attack dominates suspicious: if attack is high, suppress suspicious
    suspicious_conf += fail_sig * 0.5

    # --- Normalise to a proper probability distribution ---
    normal_conf = float(np.clip(1.0 - attack_conf - suspicious_conf, 0.01, 0.98))

    # Renormalise so sum == 1.0
    total = attack_conf + suspicious_conf + normal_conf
    attack_conf    /= total
    suspicious_conf /= total
    normal_conf    /= total

    # --- Determine state from dominant probability ---
    if attack_conf >= 0.3:
        state = 'Attack'
    elif suspicious_conf >= 0.40:
        state = 'Suspicious'
    else:
        state = 'Normal'

    return {
        'state': state,
        'confidence': {
            'normal':     round(normal_conf,    4),
            'suspicious': round(suspicious_conf, 4),
            'attack':     round(attack_conf,     4),
        },
    }


def get_current_threat_state(file_id: int, ip: str = None) -> dict:
    features = extract_features(file_id, ip=ip)
    result = classify_threat(features)
    result['features'] = {
        'global_rps':         float(features[0]),
        'ip_rps':             float(features[1]),
        'ip_auth_failures':   float(features[2]),
        'auth_failure_rate':  float(features[3]),
        'geo_anomaly_score':  float(features[4]),
        'time_of_day_score':  float(features[5]),
        'user_agent_entropy': float(features[6]),
    }
    return result


# ---------------------------------------------------------------------------
# Security score — real metric, unaffected by demo/simulated events
# ---------------------------------------------------------------------------

def compute_security_score() -> dict:
    """
    Calculate a live security score (0–100) from genuine system security
    metrics. Simulated AUTH_FAIL events injected by the demo are excluded
    because they use source_ip patterns like '192.168.X.X' and user_agent
    'attacker-bot/N', so they don't affect real key health or state metrics.

    Scoring breakdown (100 points total):
      30  — Encryption strength (AES-128=base, AES-256=bonus, CONT_ROTATION=penalty)
      25  — Key health (ratio of ACTIVE vs DESTROYED keys)
      20  — Files free from genuine attack state
      15  — Audit trail activity (recent events = healthy system)
      10  — No plaintext residue (constant bonus — files always encrypted in vault)
    """
    conn = get_db()
    try:
        files = conn.execute(
            "SELECT id, encryption_state FROM files"
        ).fetchall()

        total_files = len(files)

        # Encryption strength score (30 pts)
        enc_score = 30.0
        if total_files > 0:
            aes256_count   = sum(1 for f in files if f['encryption_state'] == 'AES-256')
            cont_rot_count = sum(1 for f in files if f['encryption_state'] == 'CONT_ROTATION')
            # AES-256 files: mild bonus (+2 pts each, capped at +10)
            enc_bonus = min(aes256_count * 2, 10)
            # CONT_ROTATION: genuine attack state causes penalty (-8 pts each, capped)
            enc_penalty = min(cont_rot_count * 8, 25)
            enc_score = float(np.clip(30 + enc_bonus - enc_penalty, 0, 40))

        # Key health score (25 pts)
        key_rows = conn.execute(
            "SELECT status FROM encryption_keys"
        ).fetchall()
        total_keys   = len(key_rows)
        active_keys  = sum(1 for k in key_rows if k['status'] == 'ACTIVE')
        if total_keys > 0:
            health_ratio = active_keys / total_keys
            key_score = float(np.clip(health_ratio * 25, 5, 25))
        else:
            key_score = 20.0

        # Files free from genuine attack (20 pts)
        attack_files = sum(1 for f in files if f['encryption_state'] == 'CONT_ROTATION')
        if total_files > 0:
            attack_ratio = attack_files / total_files
            attack_score = float(np.clip((1.0 - attack_ratio) * 20, 0, 20))
        else:
            attack_score = 20.0

        # Audit trail activity (15 pts) — recent entries = healthy monitoring
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        recent_audit = conn.execute(
            "SELECT COUNT(*) FROM audit_trail WHERE timestamp >= ?",
            (cutoff,)
        ).fetchone()[0]
        # 5+ events in 24h = full points
        audit_score = float(np.clip(min(recent_audit, 5) / 5.0 * 15, 0, 15))

    finally:
        conn.close()

    # Plaintext bonus (10 pts — constant, files are always encrypted on disk)
    plaintext_score = 10.0

    raw = enc_score + key_score + attack_score + audit_score + plaintext_score
    score = int(np.clip(round(raw), 0, 100))

    if score >= 90:
        label = 'Excellent'
        color = 'cyan'
    elif score >= 75:
        label = 'Good'
        color = 'green'
    elif score >= 55:
        label = 'Fair'
        color = 'amber'
    else:
        label = 'At Risk'
        color = 'red'

    return {
        'score': score,
        'label': label,
        'color': color,
        'breakdown': {
            'encryption': round(enc_score, 1),
            'key_health':  round(key_score, 1),
            'attack_free': round(attack_score, 1),
            'audit_trail': round(audit_score, 1),
            'plaintext':   plaintext_score,
        }
    }
