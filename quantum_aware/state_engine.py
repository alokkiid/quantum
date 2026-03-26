"""
state_engine.py -- Cryptographic state machine for Quantum-Aware Enterprise.

States:
  S1 -- NORMAL        (AES-128-GCM)
  S2 -- SUSPICIOUS    (AES-256-GCM)
  S3 -- ACTIVE_ATTACK (AES-256 + CONT_ROTATION)

Public API:
  get_file_state(file_id)                     -> str
  set_file_state(file_id, new_state)          -> None
  transition_normal_to_suspicious(file_id)    -> None  (S1->S2)
  transition_suspicious_to_attack(file_id)    -> None  (S2->S3)
  transition_attack_to_suspicious(file_id)    -> None  (S3->S2, starts hysteresis)
  transition_suspicious_to_normal(file_id)    -> None  (S2->S1, after hysteresis)
  evaluate_and_transition(file_id)            -> None  (main monitor entry point)
"""

import threading
from datetime import datetime
from database import get_db
import crypto_engine
import rotation_loop
import config


# Track hysteresis timers: {file_id: threading.Timer}
_hysteresis_timers: dict[int, threading.Timer] = {}
_timer_lock = threading.Lock()


# ---------------------------------------------------------------------------
# State accessors
# ---------------------------------------------------------------------------

def get_file_state(file_id: int) -> str:
    """Return the current encryption_state for a file."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT encryption_state FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        return row['encryption_state'] if row else 'AES-128'
    finally:
        conn.close()


def set_file_state(file_id: int, new_state: str) -> None:
    """
    Update the file's encryption_state and log a STATE_CHANGE audit event.
    """
    now = datetime.utcnow().isoformat()
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT encryption_state FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        old_state = row['encryption_state'] if row else 'UNKNOWN'

        conn.execute(
            "UPDATE files SET encryption_state = ? WHERE id = ?",
            (new_state, file_id)
        )

        conn.execute(
            "INSERT INTO audit_trail "
            "(file_id, event_type, old_state, new_state, timestamp) "
            "VALUES (?, 'STATE_CHANGE', ?, ?, ?)",
            (file_id, old_state, new_state, now)
        )
        conn.commit()
        print(f"[state_engine] file={file_id}: {old_state} -> {new_state}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Transitions
# ---------------------------------------------------------------------------

def transition_normal_to_suspicious(file_id: int) -> None:
    """
    S1 -> S2: Rotate key to AES-256, update state.
    """
    print(f"[state_engine] TRANSITION S1->S2 for file={file_id}")
    conn = get_db()
    try:
        crypto_engine.rotate_key(file_id, new_bits=256, db_conn=conn, config=config)
    finally:
        conn.close()
    set_file_state(file_id, 'AES-256')


def transition_suspicious_to_attack(file_id: int) -> None:
    """
    S2 -> S3: Set state to CONT_ROTATION, start the evasion loop.
    """
    print(f"[state_engine] TRANSITION S2->S3 for file={file_id}")
    # Cancel any pending hysteresis timer
    _cancel_hysteresis(file_id)
    set_file_state(file_id, 'CONT_ROTATION')
    rotation_loop.start_loop(file_id)


def transition_attack_to_suspicious(file_id: int) -> None:
    """
    S3 -> S2: Stop the rotation loop, revert to AES-256.
    Start a 5-minute hysteresis timer -- if no new anomalies after 5 min,
    automatically revert S2 -> S1.
    """
    print(f"[state_engine] TRANSITION S3->S2 for file={file_id}")
    rotation_loop.stop_loop(file_id)
    set_file_state(file_id, 'AES-256')
    _start_hysteresis(file_id)


def transition_suspicious_to_normal(file_id: int) -> None:
    """
    S2 -> S1: Rotate key back to AES-128, update state.
    Called after hysteresis window elapses with clean behaviour.
    """
    # Verify the file is still in AES-256 (not re-escalated)
    current = get_file_state(file_id)
    if current != 'AES-256':
        print(f"[state_engine] Hysteresis abort for file={file_id}: "
              f"state is {current}, not AES-256")
        return

    # Check ML one more time before reverting
    import ml_engine
    threat = ml_engine.get_current_threat_state(file_id)
    if threat['state'] != 'Normal':
        print(f"[state_engine] Hysteresis abort for file={file_id}: "
              f"ML still says {threat['state']}")
        return

    print(f"[state_engine] TRANSITION S2->S1 for file={file_id} (hysteresis complete)")
    conn = get_db()
    try:
        crypto_engine.rotate_key(file_id, new_bits=128, db_conn=conn, config=config)
    finally:
        conn.close()
    set_file_state(file_id, 'AES-128')


# ---------------------------------------------------------------------------
# Hysteresis timer management
# ---------------------------------------------------------------------------

def _start_hysteresis(file_id: int) -> None:
    """Start a 5-minute timer that will attempt S2 -> S1 reversion."""
    _cancel_hysteresis(file_id)
    seconds = config.HYSTERESIS_MINUTES * 60
    timer = threading.Timer(seconds, transition_suspicious_to_normal, args=(file_id,))
    timer.daemon = True
    timer.name = f"hysteresis-{file_id}"
    with _timer_lock:
        _hysteresis_timers[file_id] = timer
    timer.start()
    print(f"[state_engine] Hysteresis timer started for file={file_id} "
          f"({config.HYSTERESIS_MINUTES} min)")


def _cancel_hysteresis(file_id: int) -> None:
    """Cancel any pending hysteresis timer for a file."""
    with _timer_lock:
        timer = _hysteresis_timers.pop(file_id, None)
    if timer is not None:
        timer.cancel()
        print(f"[state_engine] Hysteresis timer cancelled for file={file_id}")


# ---------------------------------------------------------------------------
# Main evaluation entry point
# ---------------------------------------------------------------------------

def evaluate_and_transition(file_id: int) -> None:
    """
    Called by the background monitor every 10 seconds.
    Evaluates ML classification and triggers transitions if needed.

    Transition rules:
      Normal     + ML=Suspicious -> S1->S2
      Suspicious + ML=Attack     -> S2->S3
      Attack     + ML!=Attack     -> S3->S2  (never S3->S1 directly)
    """
    import ml_engine

    current_state = get_file_state(file_id)
    threat = ml_engine.get_current_threat_state(file_id)
    ml_state = threat['state']

    if current_state == 'AES-128' and ml_state == 'Suspicious':
        transition_normal_to_suspicious(file_id)

    elif current_state == 'AES-128' and ml_state == 'Attack':
        # Fast escalation: S1 -> S2 -> S3
        transition_normal_to_suspicious(file_id)
        transition_suspicious_to_attack(file_id)

    elif current_state == 'AES-256' and ml_state == 'Attack':
        transition_suspicious_to_attack(file_id)

    elif current_state == 'CONT_ROTATION' and ml_state != 'Attack':
        # Attack has ceased -- handled by rotation_loop worker,
        # but this is a safety net
        if rotation_loop.is_looping(file_id):
            pass  # let the loop worker handle it
        else:
            transition_attack_to_suspicious(file_id)
