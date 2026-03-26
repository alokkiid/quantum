"""
routes/admin_routes.py — Admin-only routes.

Routes:
  GET  /admin/dashboard          → admin dashboard page
  GET  /admin/files/data         → JSON list of ALL files (all users)
  POST /admin/rotate/<file_id>   → force key rotation to AES-256
  GET  /api/status               → live system threat status
  POST /api/simulate/attack      → inject fake access events
  POST /api/simulate/stop        → stop attack simulation
  POST /api/isolate/<file_id>    → force file to CONT_ROTATION
"""

from datetime import datetime
from flask import Blueprint, render_template, jsonify, request
from auth import require_role
from database import get_db
import crypto_engine
import config
import ml_engine
import state_engine
import rotation_loop

admin_bp = Blueprint('admin', __name__)


# ---------------------------------------------------------------------------
# GET /admin/dashboard
# ---------------------------------------------------------------------------

@admin_bp.route('/dashboard')
@require_role('admin')
def dashboard():
    """Admin dashboard."""
    return render_template('admin/dashboard.html')


@admin_bp.route('/files')
@require_role('admin')
def files_page():
    """Admin file matrix page."""
    return render_template('admin/files.html')


@admin_bp.route('/threat')
@require_role('admin')
def threat_page():
    """Threat intelligence page."""
    return render_template('admin/threat.html')


@admin_bp.route('/topology')
@require_role('admin')
def topology_page():
    """Crypto topology page."""
    return render_template('admin/topology.html')


# ---------------------------------------------------------------------------
# GET /admin/files/data  — all files from all users
# ---------------------------------------------------------------------------

@admin_bp.route('/files/data')
@require_role('admin')
def files_data():
    """Return JSON list of ALL files with user email."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT f.id, f.original_name, f.file_size, f.sha256_fingerprint, "
            "       f.encryption_state, f.created_at, f.current_key_id, "
            "       u.email AS user_email "
            "FROM files f JOIN users u ON f.user_id = u.id "
            "ORDER BY f.created_at DESC"
        ).fetchall()
        result = [dict(r) for r in rows]
    finally:
        conn.close()
    return jsonify(result)


# ---------------------------------------------------------------------------
# POST /admin/rotate/<file_id>  — force key rotation
# ---------------------------------------------------------------------------

@admin_bp.route('/rotate/<int:file_id>', methods=['POST'])
@require_role('admin')
def rotate(file_id: int):
    """Force-rotate a file's encryption key to AES-256."""
    conn = get_db()
    try:
        new_key_id = crypto_engine.rotate_key(
            file_id=file_id,
            new_bits=256,
            db_conn=conn,
            config=config,
        )
        file_row = conn.execute(
            "SELECT encryption_state FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()
        enc_state = file_row['encryption_state'] if file_row else 'AES-256'
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'new_key_id': new_key_id,
        'encryption_state': enc_state,
    })


# ---------------------------------------------------------------------------
# GET /api/status  — live system status
# ---------------------------------------------------------------------------

@admin_bp.route('/api/status')
@require_role('admin')
def api_status():
    """Return comprehensive system threat status."""
    conn = get_db()
    try:
        # All files with their state
        files = conn.execute(
            "SELECT id, encryption_state FROM files"
        ).fetchall()

        # Determine global threat level (worst state across all files)
        states = [f['encryption_state'] for f in files]
        if 'CONT_ROTATION' in states:
            global_level = 'Attack'
        elif 'AES-256' in states:
            global_level = 'Suspicious'
        else:
            global_level = 'Normal'

        # Files under active attack
        files_under_attack = [f['id'] for f in files
                              if f['encryption_state'] == 'CONT_ROTATION']

        # Aggregate ML confidence (average across all files, or default)
        if files:
            all_confs = []
            for f in files:
                try:
                    threat = ml_engine.get_current_threat_state(f['id'])
                    all_confs.append(threat['confidence'])
                except Exception:
                    all_confs.append({'normal': 0.94, 'suspicious': 0.05, 'attack': 0.01})

            avg_conf = {
                'normal': sum(c['normal'] for c in all_confs) / len(all_confs),
                'suspicious': sum(c['suspicious'] for c in all_confs) / len(all_confs),
                'attack': sum(c['attack'] for c in all_confs) / len(all_confs),
            }
        else:
            avg_conf = {'normal': 1.0, 'suspicious': 0.0, 'attack': 0.0}

        # Rotation rate per minute (ROTATION events in last 60s)
        cutoff = datetime(
            *(datetime.utcnow().timetuple()[:6])
        )
        from datetime import timedelta
        cutoff_str = (datetime.utcnow() - timedelta(seconds=60)).isoformat()
        rotation_rate = conn.execute(
            "SELECT COUNT(*) FROM audit_trail "
            "WHERE event_type = 'ROTATION' AND timestamp >= ?",
            (cutoff_str,)
        ).fetchone()[0]

        # Total destroyed keys
        keys_destroyed = conn.execute(
            "SELECT COUNT(*) FROM encryption_keys WHERE status = 'DESTROYED'"
        ).fetchone()[0]

        # Active loops count
        active_count = len(rotation_loop.active_loops)

    finally:
        conn.close()

    return jsonify({
        'global_threat_level': global_level,
        'ml_confidence': avg_conf,
        'rotation_rate_per_minute': rotation_rate,
        'keys_destroyed_total': keys_destroyed,
        'files_under_attack': files_under_attack,
        'active_loops': active_count,
        'last_updated': datetime.utcnow().isoformat(),
    })


# ---------------------------------------------------------------------------
# POST /api/simulate/attack  — inject fake events
# ---------------------------------------------------------------------------

@admin_bp.route('/api/simulate/attack', methods=['POST'])
@require_role('admin')
def simulate_attack():
    """Inject fake access_log events to trigger ML thresholds."""
    data = request.get_json(force=True)
    file_id = data.get('file_id')
    intensity = data.get('intensity', 'low')

    if file_id is None:
        return jsonify({'success': False, 'error': 'file_id required'}), 400

    # Determine how many fake events to insert
    counts = {'high': 200, 'medium': 10, 'low': 6}
    count = counts.get(intensity, 6)

    now = datetime.utcnow().isoformat()
    conn = get_db()
    try:
        # Verify the target file exists before inserting log events
        file_row = conn.execute(
            "SELECT id FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        if file_row is None:
            return jsonify({'success': False, 'error': f'File {file_id} not found'}), 404

        for i in range(count):
            conn.execute(
                "INSERT INTO access_logs "
                "(file_id, user_id, source_ip, event_type, user_agent, timestamp) "
                "VALUES (?, NULL, ?, 'AUTH_FAIL', ?, ?)",
                (file_id, f"192.168.1.{(i % 254) + 1}",
                 f"attacker-bot/{i}", now)
            )
        conn.commit()
    finally:
        conn.close()

    # Immediately evaluate state
    state_engine.evaluate_and_transition(file_id)

    # For high intensity, force-escalate to CONT_ROTATION if not there yet
    # (200 events / 60s = 3.3 rps, below the 100 rps threshold, but
    #  the user spec says high = active attack simulation)
    if intensity == 'high':
        current_state = state_engine.get_file_state(file_id)
        if current_state == 'AES-256':
            state_engine.transition_suspicious_to_attack(file_id)
        elif current_state == 'AES-128':
            state_engine.transition_normal_to_suspicious(file_id)
            state_engine.transition_suspicious_to_attack(file_id)

    current_state = state_engine.get_file_state(file_id)
    return jsonify({
        'success': True,
        'events_injected': count,
        'state': current_state,
    })


# ---------------------------------------------------------------------------
# POST /api/simulate/stop  — stop attack simulation
# ---------------------------------------------------------------------------

@admin_bp.route('/api/simulate/stop', methods=['POST'])
@require_role('admin')
def simulate_stop():
    """Stop an ongoing attack simulation."""
    data = request.get_json(force=True)
    file_id = data.get('file_id')

    if file_id is None:
        return jsonify({'success': False, 'error': 'file_id required'}), 400

    rotation_loop.stop_loop(file_id)
    state_engine.transition_attack_to_suspicious(file_id)

    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# POST /api/isolate/<file_id>  — force CONT_ROTATION
# ---------------------------------------------------------------------------

@admin_bp.route('/api/isolate/<int:file_id>', methods=['POST'])
@require_role('admin')
def isolate(file_id: int):
    """Force a file into CONT_ROTATION mode regardless of ML state."""
    state_engine.set_file_state(file_id, 'CONT_ROTATION')
    rotation_loop.start_loop(file_id)

    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# POST /api/simulate/reset  — reset everything to clean state
# ---------------------------------------------------------------------------

@admin_bp.route('/api/simulate/reset', methods=['POST'])
@require_role('admin')
def simulate_reset():
    """
    Full system reset:
    - Stop all active rotation loops
    - Set all files back to AES-128 with fresh keys
    - Clear access_logs and audit_trail tables
    """
    # 1. Stop all rotation loops
    rotation_loop.stop_all_loops()

    conn = get_db()
    try:
        # 2. Get all files
        files = conn.execute(
            "SELECT id, stored_name FROM files"
        ).fetchall()

        now = datetime.utcnow().isoformat()
        for f in files:
            fid = f['id']
            stored_name = f['stored_name']
            try:
                # Get current active key to decrypt
                key_row = conn.execute(
                    "SELECT key_data, nonce FROM encryption_keys "
                    "WHERE file_id = ? AND status = 'ACTIVE' ORDER BY id DESC LIMIT 1",
                    (fid,)
                ).fetchone()

                if key_row is None:
                    continue

                # Decrypt current file
                ciphertext = crypto_engine.read_from_vault(stored_name, config.VAULT_PATH)
                plaintext = crypto_engine.decrypt_file(ciphertext, key_row['key_data'], key_row['nonce'])

                # Mark all existing keys DESTROYED
                conn.execute(
                    "UPDATE encryption_keys SET status = 'DESTROYED', destroyed_at = ? "
                    "WHERE file_id = ?", (now, fid)
                )

                # Generate fresh AES-128 key and re-encrypt
                new_key = crypto_engine.generate_key(128)
                enc_result = crypto_engine.encrypt_file(plaintext, new_key)
                crypto_engine.save_to_vault(enc_result['ciphertext'], stored_name, config.VAULT_PATH)

                cursor = conn.execute(
                    "INSERT INTO encryption_keys (file_id, key_data, nonce, algorithm, status, created_at) "
                    "VALUES (?, ?, ?, 'AES-128', 'ACTIVE', ?)",
                    (fid, new_key, enc_result['nonce'], now)
                )
                new_key_id = cursor.lastrowid

                conn.execute(
                    "UPDATE files SET encryption_state = 'AES-128', current_key_id = ? WHERE id = ?",
                    (new_key_id, fid)
                )
            except Exception as e:
                print(f"[reset] Error resetting file {fid}: {e}")

        # 3. Clear logs
        conn.execute("DELETE FROM access_logs")
        conn.execute("DELETE FROM audit_trail")
        conn.commit()
    finally:
        conn.close()

    # 4. Reset rotation interval to default
    config.ROTATION_INTERVAL_SECONDS = 4

    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# POST /api/config/rotation-speed  — change rotation interval at runtime
# ---------------------------------------------------------------------------

@admin_bp.route('/api/config/rotation-speed', methods=['POST'])
@require_role('admin')
def set_rotation_speed():
    """Change the rotation interval. Multiplier: 1=4s, 2=2s, 5=0.8s."""
    data = request.get_json(force=True)
    multiplier = data.get('multiplier', 1)
    if multiplier not in (1, 2, 5):
        return jsonify({'success': False, 'error': 'multiplier must be 1, 2, or 5'}), 400

    base_interval = 4.0
    config.ROTATION_INTERVAL_SECONDS = base_interval / multiplier
    return jsonify({
        'success': True,
        'interval': config.ROTATION_INTERVAL_SECONDS,
        'multiplier': multiplier,
    })


# ---------------------------------------------------------------------------
# GET /api/logs/export  — CSV download of audit trail
# ---------------------------------------------------------------------------

@admin_bp.route('/api/logs/export')
@require_role('admin')
def logs_export():
    """Build CSV from audit_trail joined with files and return as download."""
    import csv
    import io

    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT a.timestamp, a.event_type, a.file_id, "
            "       COALESCE(f.original_name, 'DELETED') AS file_name, "
            "       a.old_state, a.new_state, a.key_id, a.rotation_count "
            "FROM audit_trail a "
            "LEFT JOIN files f ON a.file_id = f.id "
            "ORDER BY a.timestamp DESC"
        ).fetchall()
    finally:
        conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'event_type', 'file_id', 'file_name',
                     'old_state', 'new_state', 'key_id', 'rotation_count'])
    for r in rows:
        writer.writerow([r['timestamp'], r['event_type'], r['file_id'],
                         r['file_name'], r['old_state'], r['new_state'],
                         r['key_id'], r['rotation_count']])

    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_log.csv'}
    )

