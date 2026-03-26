"""
crypto_engine.py — AES-GCM cryptographic operations for Quantum-Aware Enterprise.

Public API:
  generate_key(bits)                        → raw key bytes
  encrypt_file(plaintext, key)              → {ciphertext, nonce, algorithm}
  decrypt_file(ciphertext, key, nonce)      → plaintext bytes
  compute_sha256(file_bytes)                → hex digest string
  save_to_vault(enc_bytes, name, path)      → None
  read_from_vault(name, path)               → bytes
  delete_from_vault(name, path)             → None
  rotate_key(file_id, new_bits, conn, cfg)  → new key id
"""

import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyNotFoundError(Exception):
    """Raised when no ACTIVE encryption key exists for a given file."""
    pass


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_key(bits: int = 128) -> bytes:
    """Generate a random AES key. bits must be 128 or 256."""
    if bits == 128:
        return os.urandom(16)
    elif bits == 256:
        return os.urandom(32)
    else:
        raise ValueError(f"Unsupported key size: {bits}. Use 128 or 256.")


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt_file(plaintext_bytes: bytes, key_bytes: bytes) -> dict:
    """
    Encrypt plaintext with AES-GCM.

    Returns:
        {
            'ciphertext': bytes,   # encrypted data (includes GCM tag)
            'nonce': bytes,        # 12-byte nonce used
            'algorithm': str       # 'AES-128' or 'AES-256'
        }
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key_bytes)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    key_len = len(key_bytes)
    if key_len == 16:
        algorithm = 'AES-128'
    elif key_len == 32:
        algorithm = 'AES-256'
    else:
        raise ValueError(f"Invalid key length: {key_len} bytes")

    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'algorithm': algorithm,
    }


def decrypt_file(ciphertext_bytes: bytes, key_bytes: bytes, nonce_bytes: bytes) -> bytes:
    """
    Decrypt AES-GCM ciphertext.

    Returns plaintext bytes.
    Raises ValueError if decryption fails (wrong key or corrupted data).
    """
    try:
        aesgcm = AESGCM(key_bytes)
        return aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def compute_sha256(file_bytes: bytes) -> str:
    """Return the SHA-256 hex digest of file_bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Vault I/O
# ---------------------------------------------------------------------------

def save_to_vault(enc_bytes: bytes, stored_name: str, vault_path: str) -> None:
    """Write encrypted bytes to vault_path/stored_name. Creates vault dir if needed."""
    os.makedirs(vault_path, exist_ok=True)
    filepath = os.path.join(vault_path, stored_name)
    with open(filepath, 'wb') as f:
        f.write(enc_bytes)


def read_from_vault(stored_name: str, vault_path: str) -> bytes:
    """Read and return bytes from vault_path/stored_name."""
    filepath = os.path.join(vault_path, stored_name)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Vault file not found: {filepath}")
    with open(filepath, 'rb') as f:
        return f.read()


def delete_from_vault(stored_name: str, vault_path: str) -> None:
    """Delete vault_path/stored_name silently (no error if missing)."""
    filepath = os.path.join(vault_path, stored_name)
    try:
        os.remove(filepath)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Key rotation (full re-encryption cycle)
# ---------------------------------------------------------------------------

def rotate_key(file_id: int, new_bits: int = 256, db_conn=None, config=None) -> int:
    """
    Full re-encryption cycle for one file.

    Steps:
      1. Get current ACTIVE key from encryption_keys
      2. Read ciphertext from vault
      3. Decrypt in memory
      4. Generate new key (new_bits)
      5. Encrypt plaintext with new key
      6. Overwrite file in vault
      7. Mark old key as DESTROYED
      8. Insert new key into encryption_keys
      9. Update files.current_key_id
     10. Update files.encryption_state
     11. Log KEY_DESTROYED + KEY_GENERATED to audit_trail
     12. Return new key id

    Args:
        file_id:  id in the files table
        new_bits: 128 or 256
        db_conn:  sqlite3 connection
        config:   config module (needs VAULT_PATH)

    Returns:
        int — the new encryption_keys.id
    """
    now = datetime.utcnow().isoformat()

    # 1. Get current ACTIVE key
    key_row = db_conn.execute(
        "SELECT id, key_data, nonce, algorithm FROM encryption_keys "
        "WHERE file_id = ? AND status = 'ACTIVE' ORDER BY id DESC LIMIT 1",
        (file_id,)
    ).fetchone()
    if key_row is None:
        raise KeyNotFoundError(f"No active key found for file_id={file_id}")

    old_key_id = key_row['id']
    old_key_data = key_row['key_data']
    old_nonce = key_row['nonce']

    # Get file info
    file_row = db_conn.execute(
        "SELECT stored_name, encryption_state FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()
    if file_row is None:
        raise ValueError(f"File not found: file_id={file_id}")

    stored_name = file_row['stored_name']
    old_state = file_row['encryption_state']

    vault_path = config.VAULT_PATH if config else 'vault/'

    # 2. Read ciphertext from vault
    ciphertext = read_from_vault(stored_name, vault_path)

    # 3. Decrypt in memory
    plaintext = decrypt_file(ciphertext, old_key_data, old_nonce)

    # 4. Generate new key
    new_key = generate_key(new_bits)

    # 5. Encrypt with new key
    enc_result = encrypt_file(plaintext, new_key)

    # 6. Overwrite in vault
    save_to_vault(enc_result['ciphertext'], stored_name, vault_path)

    new_algorithm = enc_result['algorithm']

    # 7. Mark old key as DESTROYED
    db_conn.execute(
        "UPDATE encryption_keys SET status = 'DESTROYED', destroyed_at = ? WHERE id = ?",
        (now, old_key_id)
    )

    # 8. Insert new key
    cursor = db_conn.execute(
        "INSERT INTO encryption_keys (file_id, key_data, nonce, algorithm, status, created_at) "
        "VALUES (?, ?, ?, ?, 'ACTIVE', ?)",
        (file_id, new_key, enc_result['nonce'], new_algorithm, now)
    )
    new_key_id = cursor.lastrowid

    # 9. Update files.current_key_id
    db_conn.execute(
        "UPDATE files SET current_key_id = ? WHERE id = ?",
        (new_key_id, file_id)
    )

    # 10. Update files.encryption_state
    db_conn.execute(
        "UPDATE files SET encryption_state = ? WHERE id = ?",
        (new_algorithm, file_id)
    )

    # 11. Audit trail: KEY_DESTROYED for old key
    db_conn.execute(
        "INSERT INTO audit_trail (file_id, event_type, old_state, new_state, key_id, timestamp) "
        "VALUES (?, 'KEY_DESTROYED', ?, ?, ?, ?)",
        (file_id, old_state, new_algorithm, old_key_id, now)
    )

    # 11b. Audit trail: KEY_GENERATED for new key
    db_conn.execute(
        "INSERT INTO audit_trail (file_id, event_type, old_state, new_state, key_id, timestamp) "
        "VALUES (?, 'KEY_GENERATED', ?, ?, ?, ?)",
        (file_id, old_state, new_algorithm, new_key_id, now)
    )

    db_conn.commit()
    return new_key_id
