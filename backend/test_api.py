import io
import os
import sys
import qrcode
from PIL import Image
from starlette.datastructures import Headers, UploadFile
from fastapi import HTTPException

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.utils.qr_decoder import decode_qr_code
from app.routers.scanner import decode_qr_endpoint


def create_qr_bytes(text: str) -> bytes:
    """Generates PNG bytes for a QR code encoding `text`."""
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4,
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def create_blank_image_bytes() -> bytes:
    """Generates a blank 200x200 PNG image with no QR code."""
    blank = Image.new("RGB", (200, 200), color="white")
    buffer = io.BytesIO()
    blank.save(buffer, format="PNG")
    return buffer.getvalue()


def run_all_tests():
    print("=" * 65)
    print("RUNNING TESTS: QR Shield - QR Code Decoding Module")
    print("=" * 65)

    test_url = "https://example-college-portal.edu/login"

    # Test 1: Direct OpenCV decoder function with valid QR
    print("\n[Test 1] OpenCV Decoder - Valid QR Code:")
    qr_bytes = create_qr_bytes(test_url)
    success, decoded_text, error = decode_qr_code(qr_bytes)
    assert success is True, f"Failed to decode valid QR: {error}"
    assert decoded_text == test_url, f"Expected '{test_url}', got '{decoded_text}'"
    print(f"  --> PASSED: Extracted '{decoded_text}'")

    # Test 2: Direct OpenCV decoder function with blank image
    print("\n[Test 2] OpenCV Decoder - Blank Image (No QR):")
    blank_bytes = create_blank_image_bytes()
    success, decoded_text, error = decode_qr_code(blank_bytes)
    assert success is False, "Expected failure on blank image, but succeeded"
    assert "No QR code could be detected" in error, f"Unexpected error message: {error}"
    print(f"  --> PASSED: Correctly reported: '{error}'")

    # Test 3: API Endpoint with Valid QR Code
    print("\n[Test 3] API Endpoint - Valid QR Upload:")
    upload = UploadFile(
        file=io.BytesIO(qr_bytes),
        filename="test_qr.png",
        headers=Headers({"content-type": "image/png"})
    )
    res = decode_qr_endpoint(upload)
    assert res["success"] is True
    assert res["data"] == test_url
    assert res["filename"] == "test_qr.png"
    print(f"  --> PASSED: Endpoint returned: {res}")

    # Test 4: API Endpoint with Disallowed Extension (.txt)
    print("\n[Test 4] API Endpoint - Validation (Disallowed File Extension):")
    bad_ext_upload = UploadFile(
        file=io.BytesIO(b"Sample text file"),
        filename="notes.txt",
        headers=Headers({"content-type": "text/plain"})
    )
    try:
        decode_qr_endpoint(bad_ext_upload)
        assert False, "Endpoint should have raised HTTPException 400 for bad extension."
    except HTTPException as e:
        assert e.status_code == 400
        assert "Invalid file extension" in e.detail
        print(f"  --> PASSED: Rejected with status {e.status_code}: '{e.detail}'")

    # Test 5: API Endpoint with Disallowed MIME Type
    print("\n[Test 5] API Endpoint - Validation (Mismatched MIME Type):")
    bad_mime_upload = UploadFile(
        file=io.BytesIO(qr_bytes),
        filename="qr.png",
        headers=Headers({"content-type": "application/pdf"})
    )
    try:
        decode_qr_endpoint(bad_mime_upload)
        assert False, "Endpoint should have raised HTTPException 400 for bad MIME type."
    except HTTPException as e:
        assert e.status_code == 400
        assert "Invalid file type" in e.detail
        print(f"  --> PASSED: Rejected with status {e.status_code}: '{e.detail}'")

    # Test 6: API Endpoint with Empty File
    print("\n[Test 6] API Endpoint - Validation (Empty 0-byte File):")
    empty_upload = UploadFile(
        file=io.BytesIO(b""),
        filename="empty.png",
        headers=Headers({"content-type": "image/png"})
    )
    try:
        decode_qr_endpoint(empty_upload)
        assert False, "Endpoint should have raised HTTPException 400 for empty file."
    except HTTPException as e:
        assert e.status_code == 400
        assert "file is empty" in e.detail
        print(f"  --> PASSED: Rejected with status {e.status_code}: '{e.detail}'")

    # Test 7: API Endpoint with Oversized File (> 5MB)
    print("\n[Test 7] API Endpoint - Validation (Oversized File > 5MB):")
    large_bytes = b"0" * (5 * 1024 * 1024 + 1024)  # 5 MB + 1 KB
    large_upload = UploadFile(
        file=io.BytesIO(large_bytes),
        filename="giant.png",
        headers=Headers({"content-type": "image/png"})
    )
    try:
        decode_qr_endpoint(large_upload)
        assert False, "Endpoint should have raised HTTPException 400 for oversized file."
    except HTTPException as e:
        assert e.status_code == 400
        assert "exceeds maximum allowed limit" in e.detail
        print(f"  --> PASSED: Rejected with status {e.status_code}: '{e.detail}'")

    # Test 8: API Endpoint with Non-QR Image
    print("\n[Test 8] API Endpoint - Non-QR Image:")
    blank_upload = UploadFile(
        file=io.BytesIO(blank_bytes),
        filename="blank.jpg",
        headers=Headers({"content-type": "image/jpeg"})
    )
    try:
        decode_qr_endpoint(blank_upload)
        assert False, "Endpoint should have raised HTTPException 400 for image with no QR."
    except HTTPException as e:
        assert e.status_code == 400
        assert "No QR code could be detected" in e.detail
        print(f"  --> PASSED: Rejected with status {e.status_code}: '{e.detail}'")

    # Test 9: Actual sample_qr.png file from disk
    print("\n[Test 9] API Endpoint - Testing actual 'sample_qr.png' from disk:")
    sample_file_path = os.path.join(os.path.dirname(__file__), "sample_qr.png")
    with open(sample_file_path, "rb") as f:
        file_content = f.read()
    disk_upload = UploadFile(
        file=io.BytesIO(file_content),
        filename="sample_qr.png",
        headers=Headers({"content-type": "image/png"})
    )
    res = decode_qr_endpoint(disk_upload)
    assert res["success"] is True
    assert res["filename"] == "sample_qr.png"
    assert "example-university-portal.edu" in res["data"]
    print(f"  --> PASSED: Successfully decoded actual file from disk: {res['data']}")

    # Test 10: OpenAPI Schema Verification (Binary Upload)
    print("\n[Test 10] OpenAPI Schema - Confirm Binary File Upload format:")
    from app.main import app
    schema = app.openapi()
    body_schema = schema["components"]["schemas"]["Body_decode_qr_endpoint_api_decode_post"]
    assert body_schema["properties"]["file"]["type"] == "string"
    assert body_schema["properties"]["file"]["format"] == "binary"
    print("  --> PASSED: Schema correctly specifies 'type': 'string', 'format': 'binary'")

    print("\n" + "=" * 65)
    print("ALL 10 VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_all_tests()
