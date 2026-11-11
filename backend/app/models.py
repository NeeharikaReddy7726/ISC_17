from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    """
    SQLAlchemy model representing an authenticated user account.
    Never stores plain-text passwords; stores only cryptographically secure Argon2 hashes.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # One-to-many relationship with user's scan history
    scans = relationship("ScanHistory", back_populates="owner", cascade="all, delete-orphan")


class ScanHistory(Base):
    """
    SQLAlchemy model representing an authenticated QR scan record.
    
    Security Guarantees:
    - Original URLs are NEVER stored in plaintext.
    - Stores AES-256-GCM ciphertext (with appended authentication tag) and its unique nonce.
    - Stores the SHA-256 hex digest fingerprint for indexing and duplicate detection.
    - Enforces ownership via foreign key to the User table.
    """
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    encrypted_url = Column(Text, nullable=False)
    aes_nonce = Column(String(64), nullable=False)
    url_fingerprint = Column(String(64), nullable=False, index=True)
    prediction = Column(String(50), nullable=False)
    risk_level = Column(String(50), nullable=False)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    owner = relationship("User", back_populates="scans")
