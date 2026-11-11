from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserRegister, UserLogin, UserResponse, TokenResponse
from app.utils.auth_helpers import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account"
)
def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    """
    Registers a new user account with a validated email and password.
    
    Security Guarantees:
    - Never stores plain-text passwords.
    - Hashes passwords using memory-hard Argon2id.
    - Prevents duplicate registrations with a safe 400 response.
    """
    # Check for existing account with this email
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    # Hash the password securely using Argon2
    hashed_pwd = hash_password(payload.password)

    # Create and persist the user record
    new_user = User(
        email=payload.email,
        hashed_password=hashed_pwd
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue JWT"
)
def login_user(payload: UserLogin, db: Session = Depends(get_db)):
    """
    Verifies user credentials against the stored Argon2 hash and issues a signed JWT.
    
    Security Guarantees:
    - Employs timing-safe Argon2 verification.
    - Generates a cryptographically signed HMAC-SHA256 JWT containing user identity and expiration.
    - Generic 401 error message prevents user enumeration attacks.
    """
    user = db.query(User).filter(User.email == payload.email).first()

    # Generic error message to prevent user enumeration
    invalid_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password.",
        headers={"WWW-Authenticate": "Bearer"}
    )

    if not user:
        raise invalid_credentials_exception

    if not verify_password(payload.password, user.hashed_password):
        raise invalid_credentials_exception

    # Generate signed JWT token
    token = create_access_token(user_id=user.id, email=user.email)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated user profile"
)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's details.
    
    Access Control Guarantee:
    Identity is derived directly from the verified JWT claims, not from client-supplied
    path or query parameters, preventing ID-tampering (Insecure Direct Object Reference - IDOR).
    """
    return current_user
