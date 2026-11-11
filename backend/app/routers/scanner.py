from fastapi import APIRouter, File, UploadFile, HTTPException, status
from app.utils.qr_decoder import decode_qr_code
import os

router = APIRouter(prefix="/api", tags=["Scanner"])

# Security and validation constraints
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 Megabytes


@router.post("/decode", status_code=status.HTTP_200_OK)
def decode_qr_endpoint(
    file: UploadFile = File(
        ...,
        description="Upload a QR code image file (PNG, JPG, JPEG, WEBP)",
        json_schema_extra={"format": "binary"}
    )
):
    """
    Accepts an uploaded image file, validates its format and size,
    and extracts the embedded QR code text/URL using OpenCV.

    Safety Guarantee:
    This endpoint purely inspects and decodes the image contents.
    It does NOT make outbound HTTP network calls or visit the extracted URL.
    """
    # 1. Validate file extension
    file_ext = os.path.splitext(file.filename or "")[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{file_ext}'. Allowed formats: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # 2. Validate MIME content type
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{file.content_type}'. Allowed types: {', '.join(ALLOWED_MIME_TYPES)}"
        )

    # 3. Read file contents into memory
    contents = file.file.read()

    # 4. Validate file size
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

    # 5. Decode the QR code using OpenCV
    success, decoded_text, error_message = decode_qr_code(contents)

    if not success or not decoded_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message or "Unable to detect a valid QR code in the uploaded image."
        )

    # 6. Return response with extracted raw data
    return {
        "success": True,
        "filename": file.filename,
        "file_size_bytes": file_size,
        "data": decoded_text,
        "message": "QR code successfully decoded."
    }
