"""
rotation_loop.py — Continuous key rotation evasion loop for State 3 (Active Attack).

Runs in a daemon thread, rotating keys every ROTATION_INTERVAL_SECONDS.
After each rotation, re-evaluates ML. If attack has ceased, stops the loop
and triggers transition back to Suspicious (S2).

Public API:
  start_loop(file_id)          → None  (starts daemon thread)
  stop_loop(file_id)           → None  (signals thread to stop)
  is_looping(file_id)          → bool
  get_rotation_count(file_id)  → int
"""

import threading
from datetime import datetime
from database import get_db
import crypto_engine
import config


# Active loops: {file_id: threading.Event}
active_loops: dict[int, threading.Event] = {}
_lock = threading.Lock()


def start_loop(file_id: int) -> None:
    """Start the background rotation loop for a file. No-op if already running."""
    with _lock:
        if file_id in active_loops:
            return  # already running
        stop_signal = threading.Event()
        active_loops[file_id] = stop_signal

    t = threading.Thread(
        target=_loop_worker,
        args=(file_id, stop_signal),
        daemon=True,
        name=f"rotation-loop-{file_id}",
    )
    t.start()
    print(f"[rotation_loop] Started loop for file_id={file_id}")


def stop_loop(file_id: int) -> None:
    """Signal the rotation loop for a file to stop."""
    with _lock:
        stop_signal = active_loops.pop(file_id, None)
    if stop_signal is not None:
        stop_signal.set()
        print(f"[rotation_loop] Stopped loop for file_id={file_id}")


def is_looping(file_id: int) -> bool:
    """Return True if a rotation loop is active for file_id."""
    return file_id in active_loops


def get_rotation_count(file_id: int) -> int:
    """Query audit_trail for total ROTATION events for this file."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_trail WHERE file_id = ? AND event_type = 'ROTATION'",
            (file_id,)
        ).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def stop_all_loops() -> None:
    """Stop every active rotation loop. Used by /api/simulate/reset."""
    with _lock:
        file_ids = list(active_loops.keys())
    for fid in file_ids:
        stop_loop(fid)


def _loop_worker(file_id: int, stop_signal: threading.Event) -> None:
    """
    Worker thread: rotates keys every ROTATION_INTERVAL_SECONDS.
    After each cycle, re-evaluates ML. Exits if attack has ceased.
    """
    # Import here to avoid circular imports
    import ml_engine

    cycle = 0

    while not stop_signal.is_set():
        cycle += 1
        now = datetime.utcnow().isoformat()

        try:
            conn = get_db()
            try:
                # Edge case: check file still exists before rotating
                file_check = conn.execute(
                    "SELECT id FROM files WHERE id = ?", (file_id,)
                ).fetchone()
                if file_check is None:
                    print(f"[rotation_loop] file={file_id} deleted, stopping loop")
                    break

                # Rotate key (stays at AES-256 during attack)
                new_key_id = crypto_engine.rotate_key(
                    file_id=file_id,
                    new_bits=256,
                    db_conn=conn,
                    config=config,
                )

                # Get current rotation count
                rot_count = conn.execute(
                    "SELECT COUNT(*) FROM audit_trail "
                    "WHERE file_id = ? AND event_type = 'ROTATION'",
                    (file_id,)
                ).fetchone()[0] + 1

                # Log ROTATION event
                conn.execute(
                    "INSERT INTO audit_trail "
                    "(file_id, event_type, new_state, key_id, rotation_count, timestamp) "
                    "VALUES (?, 'ROTATION', 'CONT_ROTATION', ?, ?, ?)",
                    (file_id, new_key_id, rot_count, now)
                )
                conn.commit()

                print(f"[rotation_loop] file={file_id} cycle={cycle} "
                      f"rot_count={rot_count} new_key={new_key_id}")
            finally:
                conn.close()

            # Re-evaluate ML
            threat = ml_engine.get_current_threat_state(file_id, ip=None)
            if threat['state'] != 'Attack':
                print(f"[rotation_loop] file={file_id} attack ceased "
                      f"(ML={threat['state']}), stopping loop")
                # Import state_engine here to avoid circular import
                import state_engine
                state_engine.transition_attack_to_suspicious(file_id)
                break

        except crypto_engine.KeyNotFoundError as e:
            print(f"[rotation_loop] {e} — stopping loop for file={file_id}")
            break

        except Exception as e:
            print(f"[rotation_loop] Error in cycle {cycle} for file={file_id}: {e}")

        # Read interval dynamically so runtime speed changes take effect
        interval = config.ROTATION_INTERVAL_SECONDS
        stop_signal.wait(timeout=interval)

    # Clean up if we broke out of the loop
    with _lock:
        active_loops.pop(file_id, None)

    print(f"[rotation_loop] Worker exited for file_id={file_id}")
