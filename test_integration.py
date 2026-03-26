"""
test_integration.py -- End-to-end integration test for Quantum-Aware Enterprise.

Tests the complete flow: upload -> attack -> rotation -> stop -> download -> reset -> export.
Run from project root:  python test_integration.py
"""

import sys
import os
import io
import json
import time

# Ensure we can import the app
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quantum_aware'))
sys.path.insert(0, '.')

# Clean slate: remove old DB
DB_PATH = 'quantum_aware.db'
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

from app import app

passed = 0
failed = 0
total = 12


def check(step: int, name: str, condition: bool, detail: str = ''):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] Step {step:>2}: {name}")
    else:
        failed += 1
        print(f"  [FAIL] Step {step:>2}: {name}  - {detail}")


print("\n" + "=" * 60)
print("  Quantum-Aware Enterprise -- Integration Test")
print("=" * 60 + "\n")

with app.test_client() as c:

    # -- Step 1: Login as user --
    r = c.post('/login', data={'email': 'user@qaware.com', 'password': 'user123'})
    check(1, "Login as user -> redirect to /user/files",
          r.status_code == 302 and '/user/files' in r.headers.get('Location', ''),
          f"status={r.status_code}, location={r.headers.get('Location')}")

    # -- Step 2: Upload test.txt --
    test_content = b"Hello Quantum World"
    data = {'file': (io.BytesIO(test_content), 'test.txt')}
    r = c.post('/user/upload', data=data, content_type='multipart/form-data')
    upload = r.get_json() if r.status_code == 200 else {}
    file_id = upload.get('file_id')
    check(2, "Upload test.txt -> AES-128 state",
          r.status_code == 200 and upload.get('encryption_state') == 'AES-128',
          f"status={r.status_code}, resp={upload}")

    # -- Step 3: Download and verify content --
    r = c.get(f'/user/download/{file_id}')
    check(3, "Download file -> content matches",
          r.status_code == 200 and r.data == test_content,
          f"status={r.status_code}, len={len(r.data) if r.data else 0}")

    # -- Step 4: Audit trail has KEY_GENERATED --
    c.get('/logout')
    c.post('/login', data={'email': 'admin@qaware.com', 'password': 'admin123'})
    r = c.get('/admin/api/status')
    status_data = r.get_json() if r.status_code == 200 else {}

    # Check audit_trail directly
    from database import get_db
    conn = get_db()
    key_gen_rows = conn.execute(
        "SELECT * FROM audit_trail WHERE file_id = ? AND event_type = 'KEY_GENERATED'",
        (file_id,)
    ).fetchall()
    conn.close()
    check(4, "Audit trail has KEY_GENERATED event",
          len(key_gen_rows) > 0,
          f"found {len(key_gen_rows)} KEY_GENERATED rows")

    # -- Step 5: Admin triggers simulate/attack --
    r = c.post('/admin/api/simulate/attack',
               data=json.dumps({'file_id': file_id, 'intensity': 'high'}),
               content_type='application/json')
    attack_resp = r.get_json() if r.status_code == 200 else {}
    check(5, "Simulate attack -> success",
          r.status_code == 200 and attack_resp.get('success'),
          f"status={r.status_code}, resp={attack_resp}")

    # -- Step 6: Wait -> verify rotation loop ran (ROTATION events in audit_trail) --
    print("       ... Waiting 6 seconds for rotation loop...")
    time.sleep(6)
    conn = get_db()
    rot_events = conn.execute(
        "SELECT COUNT(*) FROM audit_trail WHERE file_id = ? AND event_type = 'ROTATION'",
        (file_id,)
    ).fetchone()[0]
    conn.close()
    check(6, "Rotation loop ran (ROTATION events in audit_trail)",
          rot_events >= 1,
          f"rotation_events={rot_events}")

    # -- Step 7: Audit trail has ROTATION events --
    check(7, "Audit trail has >=1 ROTATION event",
          rot_events >= 1,
          f"found {rot_events} ROTATION rows")

    # -- Step 8: Stop attack -> state becomes AES-256 --
    r = c.post('/admin/api/simulate/stop',
               data=json.dumps({'file_id': file_id}),
               content_type='application/json')
    print("       ... Waiting 2 seconds for state transition...")
    time.sleep(2)
    conn = get_db()
    file_row = conn.execute("SELECT encryption_state FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    state_stopped = file_row['encryption_state'] if file_row else 'MISSING'
    check(8, "After stop -> state is AES-256",
          state_stopped == 'AES-256',
          f"state={state_stopped}")

    # -- Step 9: Rotation loop is no longer active --
    import rotation_loop
    check(9, "Rotation loop no longer in active_loops",
          not rotation_loop.is_looping(file_id),
          f"is_looping={rotation_loop.is_looping(file_id)}")

    # -- Step 10: Download file -> content still matches --
    c.get('/logout')
    c.post('/login', data={'email': 'user@qaware.com', 'password': 'user123'})
    r = c.get(f'/user/download/{file_id}')
    check(10, "Download after rotation -> content intact",
          r.status_code == 200 and r.data == test_content,
          f"status={r.status_code}, match={r.data == test_content if r.data else False}")

    # -- Step 11: Reset all states -> AES-128 --
    c.get('/logout')
    c.post('/login', data={'email': 'admin@qaware.com', 'password': 'admin123'})
    r = c.post('/admin/api/simulate/reset',
               data=json.dumps({}),
               content_type='application/json')
    reset_resp = r.get_json() if r.status_code == 200 else {}
    conn = get_db()
    file_row = conn.execute("SELECT encryption_state FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    state_reset = file_row['encryption_state'] if file_row else 'MISSING'
    check(11, "Reset -> all files back to AES-128",
          r.status_code == 200 and reset_resp.get('success') and state_reset == 'AES-128',
          f"status={r.status_code}, state={state_reset}")

    # -- Step 12: Export CSV --
    r = c.get('/admin/api/logs/export')
    check(12, "CSV export -> valid download",
          r.status_code == 200
          and 'text/csv' in r.content_type
          and 'attachment' in r.headers.get('Content-Disposition', ''),
          f"status={r.status_code}, type={r.content_type}")


# -- Summary --
print("\n" + "=" * 60)
print(f"  Results: {passed}/{total} tests passed")
if failed == 0:
    print("  ALL TESTS PASSED!")
else:
    print(f"  WARNING: {failed} test(s) failed")
print("=" * 60 + "\n")

sys.exit(0 if failed == 0 else 1)
