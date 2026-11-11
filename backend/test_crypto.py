"""
Automated Test Suite for Module 4: Cryptographic Security (SHA-256 + AES-256-GCM)
and Protected Scan History Access Control.

Uses an isolated in-memory SQLite database so tests remain fast, deterministic,
and do not pollute production data. Never visits or opens any decoded URLs.
"""

import base64
import hashlib
import io
import os
import sys
import qrcode
from starlette.datastructures import Headers, UploadFile
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import Base
from app.models import User, ScanHistory
from app.schemas import UserRegister, UserLogin
from app.config import AES_KEY_BYTES
from app.utils.crypto import (
    generate_url_fingerprint,
    encrypt_url,
    decrypt_url,
    CryptoDecryptionError,
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE
)
from app.utils.auth_helpers import get_current_user
from app.routers.auth import register_user, login_user
from app.routers.history import scan_and_save_qr, get_scan_history, get_single_scan
from app.main import app


# Setup isolated in-memory SQLite database for testing
TEST_ENGINE = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


def get_fresh_test_db():
    Base.metadata.drop_all(bind=TEST_ENGINE)
    Base.metadata.create_all(bind=TEST_ENGINE)
    return TestingSessionLocal()


def create_qr_bytes(text_payload: str) -> bytes:
    """Generates PNG bytes for a QR code encoding `text_payload` locally."""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(text_payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def run_all_crypto_tests():
    print("=" * 72)
    print("RUNNING TESTS: MODULE 4 (CRYPTOGRAPHIC SECURITY - SHA-256 & AES-GCM)")
    print("=" * 72)

    db = get_fresh_test_db()

    try:
        # ------------------------------------------------------------------
        # Test 1: SHA-256 Fingerprint Generation & Consistency
        # ------------------------------------------------------------------
        print("\n[Test 1] SHA-256 URL Fingerprinting & Consistency...")
        url_a = "https://example-university-portal.edu/student-login"
        url_b = "https://example-university-portal.edu/student-logout"

        fp_a1 = generate_url_fingerprint(url_a)
        fp_a2 = generate_url_fingerprint(f"  {url_a}  ")
        fp_b = generate_url_fingerprint(url_b)

        expected_sha256 = hashlib.sha256(url_a.encode("utf-8")).hexdigest()
        assert fp_a1 == expected_sha256
        assert len(fp_a1) == 64
        assert fp_a1 == fp_a2, "Identical URLs must yield identical SHA-256 fingerprints."
        assert fp_a1 != fp_b, "Different URLs must yield distinct SHA-256 fingerprints."

        try:
            generate_url_fingerprint("   ")
            assert False, "Blank URL should fail fingerprint validation"
        except ValueError:
            pass

        print(f"  --> PASSED: SHA-256 digest is 64 hex chars ({fp_a1[:16]}...), deterministic and collision-distinct.")

        # ------------------------------------------------------------------
        # Test 2: AES-256-GCM Encryption & Decryption Round Trip
        # ------------------------------------------------------------------
        print("\n[Test 2] AES-256-GCM Encryption & Decryption Round Trip...")
        test_urls = [
            "https://example-university-portal.edu/student-login",
            "http://192.168.1.50/verify-account/secure-login?token=abc123&redirect=http://evil.com",
            "https://example.org/path?query=cafe\u00e9&lang=en"
        ]
        for target_url in test_urls:
            enc_b64, nonce_b64 = encrypt_url(target_url)
            assert target_url not in enc_b64, "Encrypted output must not contain plaintext URL."

            raw_nonce = base64.b64decode(nonce_b64)
            raw_payload = base64.b64decode(enc_b64)
            assert len(raw_nonce) == GCM_NONCE_SIZE, f"Nonce must be {GCM_NONCE_SIZE} bytes."
            assert len(raw_payload) == len(target_url.encode("utf-8")) + GCM_TAG_SIZE

            decrypted = decrypt_url(enc_b64, nonce_b64)
            assert decrypted == target_url, "Decrypted URL must match original plaintext exactly."

        print("  --> PASSED: All URLs encrypted (12-byte nonce + ciphertext + 16-byte GCM tag) and decrypted cleanly.")

        # ------------------------------------------------------------------
        # Test 3: Unique Random Nonce for Repeated Encryption
        # ------------------------------------------------------------------
        print("\n[Test 3] Unique Nonces & Ciphertexts for Repeated Encryption...")
        repeated_url = "https://portal.university.edu/dashboard"
        encryptions = [encrypt_url(repeated_url) for _ in range(10)]
        nonces = [pair[1] for pair in encryptions]
        ciphertexts = [pair[0] for pair in encryptions]

        assert len(set(nonces)) == 10, "Every AES-GCM encryption must generate a unique nonce!"
        assert len(set(ciphertexts)) == 10, "Unique nonces must produce distinct ciphertexts for identical plaintext!"
        for c_b64, n_b64 in encryptions:
            assert decrypt_url(c_b64, n_b64) == repeated_url
        print("  --> PASSED: 10 repeated encryptions produced 10 unique nonces and 10 unique ciphertexts.")

        # ------------------------------------------------------------------
        # Test 4: Tampered Ciphertext, Auth Tag, and Nonce Rejection
        # ------------------------------------------------------------------
        print("\n[Test 4] Tampered Ciphertext / Corrupted Payload Rejection...")
        enc_orig, nonce_orig = encrypt_url(repeated_url)
        raw_payload = bytearray(base64.b64decode(enc_orig))

        # 4a. Flip 1 bit in the ciphertext portion (first byte)
        tampered_cipher = bytearray(raw_payload)
        tampered_cipher[0] ^= 0x01
        tampered_cipher_b64 = base64.b64encode(bytes(tampered_cipher)).decode("utf-8")
        try:
            decrypt_url(tampered_cipher_b64, nonce_orig)
            assert False, "Tampered ciphertext must raise CryptoDecryptionError"
        except CryptoDecryptionError:
            pass

        # 4b. Flip 1 bit in the 16-byte GCM authentication tag (last byte)
        tampered_tag = bytearray(raw_payload)
        tampered_tag[-1] ^= 0x80
        tampered_tag_b64 = base64.b64encode(bytes(tampered_tag)).decode("utf-8")
        try:
            decrypt_url(tampered_tag_b64, nonce_orig)
            assert False, "Tampered GCM tag must raise CryptoDecryptionError"
        except CryptoDecryptionError:
            pass

        # 4c. Wrong nonce
        wrong_nonce_b64 = base64.b64encode(os.urandom(GCM_NONCE_SIZE)).decode("utf-8")
        try:
            decrypt_url(enc_orig, wrong_nonce_b64)
            assert False, "Wrong nonce must fail GCM authentication"
        except CryptoDecryptionError:
            pass

        # 4d. Truncated payload & invalid Base64
        for bad_c, bad_n in [
            ("not-valid-base64!!!", nonce_orig),
            (base64.b64encode(b"short").decode("utf-8"), nonce_orig),
            (enc_orig, base64.b64encode(b"shortnonce").decode("utf-8")),
        ]:
            try:
                decrypt_url(bad_c, bad_n)
                assert False, "Malformed payload/nonce must raise CryptoDecryptionError"
            except CryptoDecryptionError:
                pass

        print("  --> PASSED: Bit-flipped ciphertext, forged tag, wrong nonce, and corrupted payloads rejected cleanly.")

        # ------------------------------------------------------------------
        # Test 5: Incorrect AES Key Rejection
        # ------------------------------------------------------------------
        print("\n[Test 5] Incorrect AES Key Rejection...")
        wrong_32_byte_key = bytes((b ^ 0xFF) for b in AES_KEY_BYTES)
        assert len(wrong_32_byte_key) == 32 and wrong_32_byte_key != AES_KEY_BYTES

        try:
            decrypt_url(enc_orig, nonce_orig, key=wrong_32_byte_key)
            assert False, "Incorrect 32-byte key must fail decryption"
        except CryptoDecryptionError:
            pass

        try:
            decrypt_url(enc_orig, nonce_orig, key=b"too-short-key")
            assert False, "Invalid key length must raise CryptoDecryptionError"
        except CryptoDecryptionError:
            pass

        try:
            encrypt_url(repeated_url, key=b"too-short-key")
            assert False, "Encryption with non-32-byte key must raise ValueError"
        except ValueError:
            pass

        print("  --> PASSED: Wrong AES key and invalid key sizes rejected safely without data leakage.")

        # ------------------------------------------------------------------
        # Setup Authenticated Users Alice and Bob
        # ------------------------------------------------------------------
        alice = register_user(UserRegister(email="alice@example.com", password="AlicePassword123!"), db=db)
        bob = register_user(UserRegister(email="bob@example.com", password="BobPassword123!"), db=db)

        alice_login = login_user(UserLogin(email="alice@example.com", password="AlicePassword123!"), db=db)
        bob_login = login_user(UserLogin(email="bob@example.com", password="BobPassword123!"), db=db)

        alice_user = get_current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=alice_login.access_token),
            db=db
        )
        bob_user = get_current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=bob_login.access_token),
            db=db
        )

        # ------------------------------------------------------------------
        # Test 6: End-to-End Protected QR Scan + No Plaintext in Database
        # ------------------------------------------------------------------
        print("\n[Test 6] Protected Scan Storage Without Plaintext URLs (sample_qr.png)...")
        sample_qr_path = os.path.join(os.path.dirname(__file__), "sample_qr.png")
        with open(sample_qr_path, "rb") as f:
            sample_qr_bytes = f.read()

        upload_1 = UploadFile(
            file=io.BytesIO(sample_qr_bytes),
            filename="sample_qr.png",
            headers=Headers({"content-type": "image/png"})
        )
        scan_resp_1 = scan_and_save_qr(file=upload_1, current_user=alice_user, db=db)

        expected_url = "https://example-university-portal.edu/student-login"
        assert scan_resp_1.url == expected_url
        assert scan_resp_1.previously_scanned is False
        assert scan_resp_1.previous_scan_count == 0
        assert scan_resp_1.url_fingerprint == generate_url_fingerprint(expected_url)
        assert scan_resp_1.prediction in {"Legitimate", "Phishing"}
        assert scan_resp_1.risk_level in {"Safe", "Suspicious", "High Risk"}

        # Inspect raw SQLite row to guarantee plaintext URL is NOT persisted anywhere
        raw_row = db.execute(
            text(
                "SELECT id, user_id, encrypted_url, aes_nonce, url_fingerprint, prediction, risk_level "
                "FROM scan_history WHERE id = :sid"
            ),
            {"sid": scan_resp_1.scan_id}
        ).fetchone()
        assert raw_row is not None
        row_dump = "|".join(str(col) for col in raw_row)
        assert "example-university-portal.edu" not in row_dump, "Plaintext URL leaked in SQLite!"
        assert "student-login" not in row_dump, "Plaintext URL path leaked in SQLite!"
        assert raw_row.user_id == alice.id
        assert raw_row.url_fingerprint == scan_resp_1.url_fingerprint
        assert decrypt_url(raw_row.encrypted_url, raw_row.aes_nonce) == expected_url

        print(
            f"  --> PASSED: Scan ID={scan_resp_1.scan_id} saved encrypted (ciphertext='{raw_row.encrypted_url[:20]}...', "
            f"prediction={scan_resp_1.prediction}, risk={scan_resp_1.risk_level}); zero plaintext in DB."
        )

        # ------------------------------------------------------------------
        # Test 7: Duplicate Scan Detection via SHA-256 & Nonce Uniqueness
        # ------------------------------------------------------------------
        print("\n[Test 7] Duplicate URL Detection (SHA-256) & Fresh Nonce on Re-Scan...")
        upload_2 = UploadFile(
            file=io.BytesIO(sample_qr_bytes),
            filename="sample_qr_again.png",
            headers=Headers({"content-type": "image/png"})
        )
        scan_resp_2 = scan_and_save_qr(file=upload_2, current_user=alice_user, db=db)

        assert scan_resp_2.previously_scanned is True
        assert scan_resp_2.previous_scan_count == 1
        assert scan_resp_2.url_fingerprint == scan_resp_1.url_fingerprint

        rec_1 = db.query(ScanHistory).filter(ScanHistory.id == scan_resp_1.scan_id).first()
        rec_2 = db.query(ScanHistory).filter(ScanHistory.id == scan_resp_2.scan_id).first()
        assert rec_1.aes_nonce != rec_2.aes_nonce, "Re-scanning same URL must still use a new AES nonce!"
        assert rec_1.encrypted_url != rec_2.encrypted_url
        print("  --> PASSED: Second scan flagged previously_scanned=True (count=1) while storing a fresh nonce.")

        # ------------------------------------------------------------------
        # Test 8: User-Specific Scan History Isolation & Ownership Control
        # ------------------------------------------------------------------
        print("\n[Test 8] User-Specific Scan History Isolation & Access Control...")
        phish_like_url = "http://198.51.100.42/secure-login-verify-account/update.php"
        bob_qr_bytes = create_qr_bytes(phish_like_url)
        bob_upload = UploadFile(
            file=io.BytesIO(bob_qr_bytes),
            filename="bob_qr.png",
            headers=Headers({"content-type": "image/png"})
        )

        # Even if Bob scans Alice's same URL later, Alice's history does not leak into Bob's duplicate count
        bob_same_upload = UploadFile(
            file=io.BytesIO(sample_qr_bytes),
            filename="bob_checks_sample.png",
            headers=Headers({"content-type": "image/png"})
        )
        bob_scan_same = scan_and_save_qr(file=bob_same_upload, current_user=bob_user, db=db)
        assert bob_scan_same.previously_scanned is False, "Alice's prior scan must not leak to Bob!"

        bob_scan_phish = scan_and_save_qr(file=bob_upload, current_user=bob_user, db=db)
        assert bob_scan_phish.url == phish_like_url

        # Alice sees only her 2 scans
        alice_history = get_scan_history(current_user=alice_user, db=db)
        assert len(alice_history) == 2
        assert all(item.url == expected_url for item in alice_history)

        # Bob sees only his 2 scans (none of Alice's scan IDs)
        bob_history = get_scan_history(current_user=bob_user, db=db)
        assert len(bob_history) == 2
        bob_scan_ids = {item.scan_id for item in bob_history}
        assert scan_resp_1.scan_id not in bob_scan_ids
        assert scan_resp_2.scan_id not in bob_scan_ids

        # Bob tries to directly access Alice's scan by ID -> must get 404
        try:
            get_single_scan(scan_id=scan_resp_1.scan_id, current_user=bob_user, db=db)
            assert False, "Bob must NOT be able to retrieve Alice's scan record by ID!"
        except HTTPException as e:
            assert e.status_code == 404

        # Alice CAN access her own single scan by ID
        alice_single = get_single_scan(scan_id=scan_resp_1.scan_id, current_user=alice_user, db=db)
        assert alice_single.scan_id == scan_resp_1.scan_id
        assert alice_single.url == expected_url

        # Unauthenticated request check
        try:
            get_current_user(credentials=None, db=db)
            assert False, "Missing token must fail authentication"
        except HTTPException as e:
            assert e.status_code == 401

        print("  --> PASSED: Alice and Bob scan histories are completely isolated; cross-user ID lookup blocked (HTTP 404).")

        # ------------------------------------------------------------------
        # Test 9: Database Ciphertext Tampering Detection via API
        # ------------------------------------------------------------------
        print("\n[Test 9] Safe Handling of Tampered Database Ciphertext...")
        tampered_rec = db.query(ScanHistory).filter(ScanHistory.id == scan_resp_1.scan_id).first()
        tampered_bytes = bytearray(base64.b64decode(tampered_rec.encrypted_url))
        tampered_bytes[0] ^= 0xFF
        tampered_rec.encrypted_url = base64.b64encode(bytes(tampered_bytes)).decode("utf-8")
        db.commit()

        try:
            get_single_scan(scan_id=scan_resp_1.scan_id, current_user=alice_user, db=db)
            assert False, "Tampered DB record must trigger integrity error"
        except HTTPException as e:
            assert e.status_code == 500
            assert "integrity failure" in e.detail.lower()
            err_detail = e.detail

        try:
            get_scan_history(current_user=alice_user, db=db)
            assert False, "Tampered DB record in history list must trigger integrity error"
        except HTTPException as e2:
            assert e2.status_code == 500
            assert "integrity failure" in e2.detail.lower()

        print(f"  --> PASSED: Tampered DB record safely blocked with HTTP 500: '{err_detail}'")

        # ------------------------------------------------------------------
        # Test 10: OpenAPI & Swagger Binary Upload + Security Schema Check
        # ------------------------------------------------------------------
        print("\n[Test 10] OpenAPI Schema Verification (/api/scan, /api/history)...")
        schema = app.openapi()
        assert "/api/scan" in schema["paths"]
        assert "/api/history" in schema["paths"]
        assert "/api/history/{scan_id}" in schema["paths"]

        # Verify HTTPBearer protection on all Module 4 endpoints
        for route_path, method in [
            ("/api/scan", "post"),
            ("/api/history", "get"),
            ("/api/history/{scan_id}", "get"),
        ]:
            sec = schema["paths"][route_path][method].get("security", [])
            assert any("HTTPBearer" in entry for entry in sec), f"{route_path} missing HTTPBearer auth!"

        # Verify /api/scan upload field renders as binary file picker in Swagger
        scan_body_ref = schema["paths"]["/api/scan"]["post"]["requestBody"]["content"]["multipart/form-data"]["schema"]["$ref"]
        schema_name = scan_body_ref.split("/")[-1]
        file_prop = schema["components"]["schemas"][schema_name]["properties"]["file"]
        assert file_prop["type"] == "string" and file_prop["format"] == "binary"

        print("  --> PASSED: Module 4 routes registered with HTTPBearer auth and binary Swagger upload schema.")

        print("\n" + "=" * 72)
        print("ALL 10 CRYPTOGRAPHIC SECURITY & HISTORY ISOLATION TESTS PASSED!")
        print("=" * 72)

    finally:
        db.close()


if __name__ == "__main__":
    run_all_crypto_tests()
