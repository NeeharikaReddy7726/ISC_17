from datetime import datetime
from typing import List
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator


class UserRegister(BaseModel):
    """Schema for validating new user registration requests."""
    email: EmailStr
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password must be between 8 and 128 characters."
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def password_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Password cannot consist solely of whitespace.")
        return v


class UserLogin(BaseModel):
    """Schema for validating login credentials."""
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class UserResponse(BaseModel):
    """Public representation of a user (explicitly excludes password_hash)."""
    id: int
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """Response returned upon successful login containing the JWT token."""
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class ScanResponse(BaseModel):
    """Response returned after an authenticated QR code scan and ML evaluation."""
    scan_id: int
    url: str
    url_fingerprint: str
    previously_scanned: bool
    previous_scan_count: int
    prediction: str
    risk_level: str
    confidence_percentage: float
    warnings: List[str]
    scanned_at: datetime


class ScanHistoryItem(BaseModel):
    """Decrypted scan history record belonging to the authenticated user."""
    scan_id: int
    url: str
    url_fingerprint: str
    prediction: str
    risk_level: str
    scanned_at: datetime
