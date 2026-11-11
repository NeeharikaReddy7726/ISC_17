"""
Automated Test Suite for Module 3: User Authentication and Access Control.
Uses an isolated in-memory SQLite database so tests remain fast, deterministic,
and do not pollute production data.
"""

import os
import sys
from datetime import timedelta
import jwt
from pydantic import ValidationError
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import Base
from app.models import User
from app.schemas import UserRegister, UserLogin, UserResponse
from app.config import JWT_SECRET_KEY, JWT_ALGORITHM
from app.utils.auth_helpers import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)
from app.routers.auth import register_user, login_user, get_me
from app.main import app


# Setup isolated in-memory SQLite database for testing
TEST_ENGINE = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


def get_fresh_test_db():
    Base.metadata.drop_all(bind=TEST_ENGINE)
    Base.metadata.create_all(bind=TEST_ENGINE)
    return TestingSessionLocal()


def run_all_auth_tests():
    print("=" * 68)
    print("RUNNING TESTS: MODULE 3 (AUTHENTICATION & ACCESS CONTROL)")
    print("=" * 68)

    db = get_fresh_test_db()

    try:
        # ------------------------------------------------------------------
        # Test 1: Argon2 Password Hashing
        # ------------------------------------------------------------------
        print("\n[Test 1] Argon2 Password Hashing & Verification...")
        plain = "SecurePassword123!"
        hashed = hash_password(plain)
        assert hashed != plain, "Password hash must never equal plain-text!"
        assert hashed.startswith("$argon2"), f"Expected Argon2 hash prefix, got: {hashed[:15]}"
        assert verify_password(plain, hashed) is True
        assert verify_password("WrongPassword!", hashed) is False
        print(f"  --> PASSED: Argon2 hash generated ({hashed[:25]}...) and verified cleanly.")

        # ------------------------------------------------------------------
        # Test 2: Input Validation (Email & Password Rules)
        # ------------------------------------------------------------------
        print("\n[Test 2] Input Validation (Pydantic Schemas)...")
        try:
            UserRegister(email="not-an-email", password="ValidPassword123")
            assert False, "Should have failed invalid email validation"
        except ValidationError:
            pass

        try:
            UserRegister(email="user@example.com", password="123")
            assert False, "Should have failed short password validation"
        except ValidationError:
            pass

        try:
            UserRegister(email="user@example.com", password="        ")
            assert False, "Should have failed whitespace-only password validation"
        except ValidationError:
            pass

        normalized = UserRegister(email="  Alice@Example.COM ", password="StrongPassword99!")
        assert normalized.email == "alice@example.com"
        print("  --> PASSED: Invalid emails, short passwords, and whitespace rejected; emails normalized.")

        # ------------------------------------------------------------------
        # Test 3: Successful Registration
        # ------------------------------------------------------------------
        print("\n[Test 3] User Registration (POST /api/auth/register)...")
        reg_payload = UserRegister(email="alice@example.com", password="StrongPassword99!")
        alice_db = register_user(payload=reg_payload, db=db)
        assert alice_db.id == 1
        assert alice_db.email == "alice@example.com"
        assert alice_db.hashed_password.startswith("$argon2")
        assert alice_db.created_at is not None

        # Verify UserResponse strips password hash
        alice_public = UserResponse.model_validate(alice_db)
        assert not hasattr(alice_public, "hashed_password")
        print(f"  --> PASSED: Registered user ID={alice_db.id}, email='{alice_db.email}' (Argon2 hash stored).")

        # ------------------------------------------------------------------
        # Test 4: Duplicate Registration Prevention
        # ------------------------------------------------------------------
        print("\n[Test 4] Duplicate Registration Prevention...")
        dup_payload = UserRegister(email="ALICE@example.com", password="AnotherPassword88!")
        try:
            register_user(payload=dup_payload, db=db)
            assert False, "Duplicate email should have been rejected"
        except HTTPException as e:
            assert e.status_code == 400
            assert "already exists" in e.detail
            print(f"  --> PASSED: Correctly blocked duplicate email with HTTP {e.status_code}: '{e.detail}'")

        # ------------------------------------------------------------------
        # Test 5: Successful Login & JWT Claims
        # ------------------------------------------------------------------
        print("\n[Test 5] User Login & JWT Issuance (POST /api/auth/login)...")
        login_payload = UserLogin(email="alice@example.com", password="StrongPassword99!")
        token_resp = login_user(payload=login_payload, db=db)
        assert token_resp.token_type == "bearer"
        assert token_resp.expires_in_minutes > 0
        alice_token = token_resp.access_token

        decoded = jwt.decode(alice_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert decoded["sub"] == "alice@example.com"
        assert decoded["user_id"] == 1
        assert "exp" in decoded and "iat" in decoded
        print(f"  --> PASSED: Issued signed JWT containing sub='{decoded['sub']}', user_id={decoded['user_id']}.")

        # ------------------------------------------------------------------
        # Test 6: Invalid Credentials (Wrong Password & Missing User)
        # ------------------------------------------------------------------
        print("\n[Test 6] Incorrect Password & Non-Existent Email...")
        try:
            login_user(payload=UserLogin(email="alice@example.com", password="WrongPassword!"), db=db)
            assert False, "Wrong password should raise 401"
        except HTTPException as e:
            assert e.status_code == 401

        try:
            login_user(payload=UserLogin(email="nobody@example.com", password="StrongPassword99!"), db=db)
            assert False, "Unknown user should raise 401"
        except HTTPException as e:
            assert e.status_code == 401
        print("  --> PASSED: Both wrong password and unknown email rejected with HTTP 401 Unauthorized.")

        # ------------------------------------------------------------------
        # Test 7: Protected Endpoint Access (GET /api/auth/me)
        # ------------------------------------------------------------------
        print("\n[Test 7] Protected Endpoint Access with Valid JWT...")
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=alice_token)
        authenticated_user = get_current_user(credentials=creds, db=db)
        me_resp = get_me(current_user=authenticated_user)
        assert me_resp.id == 1
        assert me_resp.email == "alice@example.com"
        print(f"  --> PASSED: Protected /me returned profile for '{me_resp.email}'.")

        # ------------------------------------------------------------------
        # Test 8: Missing, Invalid, Tampered, and Expired JWT Tokens
        # ------------------------------------------------------------------
        print("\n[Test 8] Missing, Invalid, Tampered, and Expired JWT Handling...")

        # 8a. Missing credentials
        try:
            get_current_user(credentials=None, db=db)
            assert False, "Missing token should raise 401"
        except HTTPException as e:
            assert e.status_code == 401

        # 8b. Malformed token
        try:
            bad_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="not.a.valid.jwt")
            get_current_user(credentials=bad_creds, db=db)
            assert False, "Malformed token should raise 401"
        except HTTPException as e:
            assert e.status_code == 401

        # 8c. Token signed with wrong secret key
        wrong_key = "wrong-secret-key-that-is-at-least-32-bytes-long"
        forged_token = jwt.encode({"sub": "alice@example.com", "user_id": 1}, wrong_key, algorithm="HS256")
        try:
            forged_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=forged_token)
            get_current_user(credentials=forged_creds, db=db)
            assert False, "Forged token should raise 401"
        except HTTPException as e:
            assert e.status_code == 401

        # 8d. Expired token
        expired_token = create_access_token(user_id=1, email="alice@example.com", expires_delta=timedelta(seconds=-10))
        try:
            exp_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)
            get_current_user(credentials=exp_creds, db=db)
            assert False, "Expired token should raise 401"
        except HTTPException as e:
            assert e.status_code == 401
            assert "expired" in e.detail.lower()

        print("  --> PASSED: Missing, malformed, forged, and expired tokens all safely rejected (HTTP 401).")

        # ------------------------------------------------------------------
        # Test 9: Multi-User Isolation (Prevent ID Tampering)
        # ------------------------------------------------------------------
        print("\n[Test 9] Access Control Isolation (User B vs User A)...")
        bob_db = register_user(
            payload=UserRegister(email="bob@example.com", password="BobPassword2026!"),
            db=db
        )
        bob_token_resp = login_user(
            payload=UserLogin(email="bob@example.com", password="BobPassword2026!"),
            db=db
        )
        bob_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=bob_token_resp.access_token)
        current_bob = get_current_user(credentials=bob_creds, db=db)
        bob_me = get_me(current_user=current_bob)

        assert bob_me.id == 2
        assert bob_me.email == "bob@example.com"
        assert bob_me.id != alice_db.id
        print("  --> PASSED: Bob's token strictly resolves to Bob (ID=2); cannot read Alice's data (ID=1).")

        # ------------------------------------------------------------------
        # Test 10: OpenAPI & Security Scheme Verification
        # ------------------------------------------------------------------
        print("\n[Test 10] OpenAPI Security Schema Check...")
        openapi = app.openapi()
        assert "/api/auth/register" in openapi["paths"]
        assert "/api/auth/login" in openapi["paths"]
        assert "/api/auth/me" in openapi["paths"]
        assert "HTTPBearer" in openapi["components"]["securitySchemes"]
        me_security = openapi["paths"]["/api/auth/me"]["get"].get("security", [])
        assert any("HTTPBearer" in sec for sec in me_security)
        print("  --> PASSED: Auth endpoints and HTTPBearer scheme properly registered in OpenAPI/Swagger.")

        print("\n" + "=" * 68)
        print("ALL 10 AUTHENTICATION & ACCESS CONTROL TESTS PASSED!")
        print("=" * 68)

    finally:
        db.close()


if __name__ == "__main__":
    run_all_auth_tests()
