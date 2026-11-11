import os
from typing import List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, ScanHistory
from app.schemas import ScanResponse, ScanHistoryItem
from app.utils.auth_helpers import get_current_user
from app.utils.qr_decoder import decode_qr_code
from app.utils.crypto import (
    generate_url_fingerprint,
    encrypt_url,
    decrypt_url,
    CryptoDecryptionError
)
from app.ml.predictor import predict_url

router = APIRouter(prefix="/api", tags=["Secure Scanning & History"])

# Validation constraints matching Module 1
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 Megabytes


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def scan_and_save_qr(
    file: UploadFile = File(
        ...,
        description="Upload a QR code image file (PNG, JPG, JPEG, WEBP)",
        json_schema_extra={"format": "binary"}
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Protected end-to-end QR scanning endpoint:
    1. Verifies JWT authentication.
    2. Validates image format and file size.
    3. Decodes the QR code using OpenCV (without opening the URL).
    4. Evaluates phishing risk using the trained Random Forest classifier.
    5. Computes a SHA-256 fingerprint to detect duplicate scans for this user.
    6. Encrypts the URL using AES-256-GCM with a unique random nonce.
    7. Saves the encrypted scan record to SQLite (never storing plaintext URLs).
    """
    # 1. Validate file extension and MIME type
    file_ext = os.path.splitext(file.filename or "")[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{file_ext}'. Allowed formats: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{file.content_type}'. Allowed types: {', '.join(ALLOWED_MIME_TYPES)}"
        )

    # 2. Read and validate file size
    contents = file.file.read()
    file_size = len(contents)
    if file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty."
        )
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size ({file_size / (1024 * 1024):.2f} MB) exceeds maximum allowed limit of 5 MB."
        )

    # 3. Decode QR code using OpenCV
    success, decoded_url, error_message = decode_qr_code(contents)
    if not success or not decoded_url or not decoded_url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message or "Unable to detect a valid QR code in the uploaded image."
        )

    decoded_url = decoded_url.strip()

    # 4. Run ML Phishing Prediction
    ml_result = predict_url(decoded_url)
    prediction = ml_result["prediction"]
    risk_level = ml_result["risk_level"]
    confidence = ml_result["confidence_percentage"]
    warnings = ml_result["warnings"]

    # 5. Compute SHA-256 URL fingerprint & check if previously scanned by this user
    fingerprint = generate_url_fingerprint(decoded_url)
    previous_scan_count = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.url_fingerprint == fingerprint
        )
        .count()
    )
    previously_scanned = previous_scan_count > 0

    # 6. Encrypt URL using AES-256-GCM (produces Base64 ciphertext+tag and unique nonce)
    encrypted_url_b64, aes_nonce_b64 = encrypt_url(decoded_url)

    # 7. Store encrypted record in database (NO plaintext URL stored)
    scan_record = ScanHistory(
        user_id=current_user.id,
        encrypted_url=encrypted_url_b64,
        aes_nonce=aes_nonce_b64,
        url_fingerprint=fingerprint,
        prediction=prediction,
        risk_level=risk_level
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    return ScanResponse(
        scan_id=scan_record.id,
        url=decoded_url,
        url_fingerprint=fingerprint,
        previously_scanned=previously_scanned,
        previous_scan_count=previous_scan_count,
        prediction=prediction,
        risk_level=risk_level,
        confidence_percentage=confidence,
        warnings=warnings,
        scanned_at=scan_record.scanned_at
    )


@router.get("/history", response_model=List[ScanHistoryItem], status_code=status.HTTP_200_OK)
def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves and decrypts the authenticated user's scan history.
    
    Access Control Guarantee:
    Queries strictly filter by current_user.id derived from the verified JWT.
    """
    records = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.scanned_at.desc(), ScanHistory.id.desc())
        .all()
    )

    history_items = []
    for rec in records:
        try:
            decrypted_url = decrypt_url(rec.encrypted_url, rec.aes_nonce)
        except CryptoDecryptionError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Data integrity failure while decrypting scan record ID {rec.id}."
            )

        history_items.append(
            ScanHistoryItem(
                scan_id=rec.id,
                url=decrypted_url,
                url_fingerprint=rec.url_fingerprint,
                prediction=rec.prediction,
                risk_level=rec.risk_level,
                scanned_at=rec.scanned_at
            )
        )

    return history_items


@router.get("/history/{scan_id}", response_model=ScanHistoryItem, status_code=status.HTTP_200_OK)
def get_single_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves and decrypts a single scan record by ID, strictly verifying ownership.
    
    Access Control Guarantee:
    Filters by BOTH ScanHistory.id AND ScanHistory.user_id == current_user.id.
    Returns 404 if the scan does not exist OR belongs to another user.
    """
    record = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.id == scan_id,
            ScanHistory.user_id == current_user.id
        )
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )

    try:
        decrypted_url = decrypt_url(record.encrypted_url, record.aes_nonce)
    except CryptoDecryptionError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data integrity failure while decrypting the requested scan record."
        )

    return ScanHistoryItem(
        scan_id=record.id,
        url=decrypted_url,
        url_fingerprint=record.url_fingerprint,
        prediction=record.prediction,
        risk_level=record.risk_level,
        scanned_at=record.scanned_at
    )
