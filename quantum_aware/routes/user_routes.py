"""
routes/user_routes.py — User-facing file management routes.

Routes:
  POST /user/upload          → upload and encrypt a file
  GET  /user/download/<id>   → decrypt and stream a file
  POST /user/delete/<id>     → delete a file + keys + vault entry
  GET  /user/files/data      → JSON list of user's files
  GET  /user/files           → stub page (template)
"""

import io
import uuid
from datetime import datetime
from flask import (
    Blueprint, request, jsonify, session,
    send_file, render_template, abort,
)
from auth import require_role
from database import get_db
import crypto_engine
import config

user_bp = Blueprint('user', __name__)


# ---------------------------------------------------------------------------
# GET /user/files  — page stub
# ---------------------------------------------------------------------------

@user_bp.route('/files')
@require_role('user')
def files():
    """User file listing page."""
    return render_template('user/files.html')


@user_bp.route('/upload')
@require_role('user')
def upload_page():
    """Upload page (GET only — form view)."""
    return render_template('user/upload.html')


# ---------------------------------------------------------------------------
# GET /user/files/data  — JSON listing of current user's files
# ---------------------------------------------------------------------------

@user_bp.route('/files/data')
@require_role('user')
def files_data():
    """Return JSON list of the current user's files."""
    user_id = session['user_id']
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, original_name, file_size, sha256_fingerprint, "
            "       encryption_state, created_at, current_key_id "
            "FROM files WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        result = [dict(r) for r in rows]
    finally:
        conn.close()
    return jsonify(result)


# ---------------------------------------------------------------------------
# POST /user/upload  — upload + encrypt a file
# ---------------------------------------------------------------------------

@user_bp.route('/upload', methods=['POST'])
@require_role('user')
def upload():
    """Accept a file, encrypt with AES-128-GCM, store in vault."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    uploaded = request.files['file']
    if uploaded.filename == '':
        return jsonify({'success': False, 'error': 'Empty filename'}), 400

    user_id = session['user_id']
    now = datetime.utcnow().isoformat()

    # Read file bytes
    plaintext = uploaded.read()
    file_size = len(plaintext)
    original_name = uploaded.filename

    # SHA-256 fingerprint
    fingerprint = crypto_engine.compute_sha256(plaintext)

    # Generate AES-128 key and encrypt
    key = crypto_engine.generate_key(128)
    enc_result = crypto_engine.encrypt_file(plaintext, key)

    # UUID-based stored name
    stored_name = str(uuid.uuid4()) + '.enc'

    # Save to vault
    crypto_engine.save_to_vault(enc_result['ciphertext'], stored_name, config.VAULT_PATH)

    conn = get_db()
    try:
        # Insert file row
        cursor = conn.execute(
            "INSERT INTO files "
            "(user_id, original_name, stored_name, file_size, sha256_fingerprint, "
            " encryption_state, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, original_name, stored_name, file_size, fingerprint,
             enc_result['algorithm'], now)
        )
        file_id = cursor.lastrowid

        # Insert encryption key
        key_cursor = conn.execute(
            "INSERT INTO encryption_keys "
            "(file_id, key_data, nonce, algorithm, status, created_at) "
            "VALUES (?, ?, ?, ?, 'ACTIVE', ?)",
            (file_id, key, enc_result['nonce'], enc_result['algorithm'], now)
        )
        key_id = key_cursor.lastrowid

        # Update files.current_key_id
        conn.execute(
            "UPDATE files SET current_key_id = ? WHERE id = ?",
            (key_id, file_id)
        )

        # Audit trail: KEY_GENERATED
        conn.execute(
            "INSERT INTO audit_trail "
            "(file_id, event_type, new_state, key_id, timestamp) "
            "VALUES (?, 'KEY_GENERATED', ?, ?, ?)",
            (file_id, enc_result['algorithm'], key_id, now)
        )

        # Access log: UPLOAD
        conn.execute(
            "INSERT INTO access_logs "
            "(file_id, user_id, source_ip, event_type, user_agent, timestamp) "
            "VALUES (?, ?, ?, 'UPLOAD', ?, ?)",
            (file_id, user_id, request.remote_addr,
             request.headers.get('User-Agent', ''), now)
        )

        conn.commit()
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'file_id': file_id,
        'fingerprint': fingerprint,
        'stored_name': stored_name,
        'encryption_state': enc_result['algorithm'],
    })


# ---------------------------------------------------------------------------
# GET /user/download/<file_id>  — decrypt and stream
# ---------------------------------------------------------------------------

@user_bp.route('/download/<int:file_id>')
@require_role('user')
def download(file_id: int):
    """Decrypt a file in memory and return it as a download."""
    user_id = session['user_id']
    now = datetime.utcnow().isoformat()

    conn = get_db()
    try:
        # Verify ownership
        file_row = conn.execute(
            "SELECT id, user_id, original_name, stored_name FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()

        if file_row is None:
            return jsonify({'success': False, 'error': 'File not found'}), 404

        # Allow if user owns file 
        if file_row['user_id'] != user_id :
            abort(403)

        # Get ACTIVE key
        key_row = conn.execute(
            "SELECT key_data, nonce FROM encryption_keys "
            "WHERE file_id = ? AND status = 'ACTIVE' ORDER BY id DESC LIMIT 1",
            (file_id,)
        ).fetchone()

        if key_row is None:
            return jsonify({'success': False, 'error': 'No active key found'}), 500

        # Read from vault
        ciphertext = crypto_engine.read_from_vault(
            file_row['stored_name'], config.VAULT_PATH
        )

        # Decrypt
        plaintext = crypto_engine.decrypt_file(
            ciphertext, key_row['key_data'], key_row['nonce']
        )

        # Log DOWNLOAD event
        conn.execute(
            "INSERT INTO access_logs "
            "(file_id, user_id, source_ip, event_type, user_agent, timestamp) "
            "VALUES (?, ?, ?, 'DOWNLOAD', ?, ?)",
            (file_id, user_id, request.remote_addr,
             request.headers.get('User-Agent', ''), now)
        )
        conn.commit()
    finally:
        conn.close()

    # Evaluate with real caller IP for per-IP metrics 
    import state_engine
    state_engine.evaluate_and_transition(file_id, ip=request.remote_addr)

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_row['original_name'],
        mimetype='application/octet-stream',
    )


# ---------------------------------------------------------------------------
# POST /user/delete/<file_id>  — delete file, keys, vault entry
# ---------------------------------------------------------------------------

@user_bp.route('/delete/<int:file_id>', methods=['POST'])
@require_role('user')
def delete(file_id: int):
    """Delete a file: DESTROY all keys, remove from vault, delete DB row."""
    user_id = session['user_id']
    now = datetime.utcnow().isoformat()

    conn = get_db()
    try:
        # Verify ownership
        file_row = conn.execute(
            "SELECT id, user_id, stored_name FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()

        if file_row is None:
            return jsonify({'success': False, 'error': 'File not found'}), 404

        if file_row['user_id'] != user_id:
            abort(403)

        # Mark all keys as DESTROYED
        conn.execute(
            "UPDATE encryption_keys SET status = 'DESTROYED', destroyed_at = ? "
            "WHERE file_id = ?",
            (now, file_id)
        )

        # Delete from vault
        crypto_engine.delete_from_vault(file_row['stored_name'], config.VAULT_PATH)

        # Clean up referencing rows before deleting the file
        conn.execute("DELETE FROM access_logs WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM audit_trail WHERE file_id = ?", (file_id,))

        # Delete file row (cascade will remove key rows if FK cascade is set,
        # but we already marked them DESTROYED above for audit clarity)
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))

        conn.commit()
    finally:
        conn.close()

    return jsonify({'success': True})
