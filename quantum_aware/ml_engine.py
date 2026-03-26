"""
ml_engine.py — ML threat classification for Quantum-Aware Enterprise.

Rule-based v1 classifier using access_logs feature extraction.

Public API:
  extract_features(file_id, window_seconds)  → np.array (5 features)
  classify_threat(feature_vector)            → {state, confidence}
  get_current_threat_state(file_id)          → {state, confidence, features}
"""

import numpy as np
from datetime import datetime, timedelta
from database import get_db


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(file_id: int, window_seconds: int = 60) -> np.ndarray:
    """
    Build a 5-feature vector from recent access_logs for the given file.

    Features:
      [0] request_rate       — total events / window_seconds
      [1] auth_failure_rate  — AUTH_FAIL count / max(total, 1)
      [2] geo_anomaly_score  — unique IPs / max(total, 1)
      [3] time_of_day_score  — 0.8 if nighttime (22–06), else 0.2
      [4] user_agent_entropy — unique UAs / max(total, 1)
    """
    cutoff = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat()

    conn = get_db()
    try:
        # All events in the window for this file
        rows = conn.execute(
            "SELECT event_type, source_ip, user_agent FROM access_logs "
            "WHERE file_id = ? AND timestamp >= ?",
            (file_id, cutoff)
        ).fetchall()

        # Also count events with NULL file_id (global auth failures, etc.)
        global_rows = conn.execute(
            "SELECT event_type, source_ip, user_agent FROM access_logs "
            "WHERE (file_id = ? OR file_id IS NULL) AND timestamp >= ?",
            (file_id, cutoff)
        ).fetchall()
    finally:
        conn.close()

    # Combine — use file-specific rows primarily, global for auth failures
    all_rows = rows if len(rows) > 0 else global_rows
    total = len(all_rows)

    # Feature 1: request rate
    request_rate = total / max(window_seconds, 1)

    # Feature 2: auth failure rate
    auth_fails = sum(1 for r in all_rows if r['event_type'] == 'AUTH_FAIL')
    auth_failure_rate = auth_fails / max(total, 1)

    # Feature 3: geo anomaly (unique IPs / total)
    unique_ips = len(set(r['source_ip'] for r in all_rows if r['source_ip']))
    geo_anomaly_score = unique_ips / max(total, 1)

    # Feature 4: time of day
    hour = datetime.utcnow().hour
    time_of_day_score = 0.8 if (hour >= 22 or hour < 6) else 0.2

    # Feature 5: user agent entropy
    unique_uas = len(set(r['user_agent'] for r in all_rows if r['user_agent']))
    user_agent_entropy = unique_uas / max(total, 1)

    return np.array([
        request_rate,
        auth_failure_rate,
        geo_anomaly_score,
        time_of_day_score,
        user_agent_entropy,
    ])


# ---------------------------------------------------------------------------
# Classification (rule-based v1)
# ---------------------------------------------------------------------------

def classify_threat(feature_vector: np.ndarray) -> dict:
    """
    Rule-based threat classifier.

    Thresholds:
      request_rate >= 100       → Attack  (confidence 0.95)
      auth_failure_rate >= 0.4  → Suspicious (confidence 0.85)
      else                     → Normal (confidence 0.94)

    Returns:
      {'state': str, 'confidence': {'normal': float, 'suspicious': float, 'attack': float}}
    """
    req_rate = feature_vector[0]
    fail_rate = feature_vector[1]

    if req_rate >= 100:
        return {
            'state': 'Attack',
            'confidence': {'normal': 0.02, 'suspicious': 0.03, 'attack': 0.95},
        }
    elif fail_rate >= 0.4:
        return {
            'state': 'Suspicious',
            'confidence': {'normal': 0.10, 'suspicious': 0.85, 'attack': 0.05},
        }
    else:
        return {
            'state': 'Normal',
            'confidence': {'normal': 0.94, 'suspicious': 0.05, 'attack': 0.01},
        }


# ---------------------------------------------------------------------------
# Combined helper
# ---------------------------------------------------------------------------

def get_current_threat_state(file_id: int) -> dict:
    """
    Extract features, classify, and return the full result.

    Returns:
      {
        'state': str,
        'confidence': {...},
        'features': {request_rate, auth_failure_rate, geo_anomaly, tod, ua_entropy}
      }
    """
    features = extract_features(file_id)
    result = classify_threat(features)
    result['features'] = {
        'request_rate': float(features[0]),
        'auth_failure_rate': float(features[1]),
        'geo_anomaly_score': float(features[2]),
        'time_of_day_score': float(features[3]),
        'user_agent_entropy': float(features[4]),
    }
    return result
