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


def classify_threat(feature_vector: np.ndarray) -> dict:
    global_rps        = feature_vector[0]
    ip_rps            = feature_vector[1]
    ip_auth_failures  = feature_vector[2]
    auth_failure_rate = feature_vector[3]

    if global_rps >= 100 or ip_rps >= 50:
        return {
            'state': 'Attack',
            'confidence': {'normal': 0.02, 'suspicious': 0.03, 'attack': 0.95},
        }

    if ip_auth_failures >= 5 or auth_failure_rate >= 0.4:
        return {
            'state': 'Suspicious',
            'confidence': {'normal': 0.10, 'suspicious': 0.85, 'attack': 0.05},
        }

    return {
        'state': 'Normal',
        'confidence': {'normal': 0.94, 'suspicious': 0.05, 'attack': 0.01},
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
