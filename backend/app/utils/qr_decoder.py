import cv2
import numpy as np
from typing import Tuple, Optional


def decode_qr_code(image_bytes: bytes) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Decodes a QR code from raw image bytes using OpenCV.

    Parameters:
        image_bytes: The raw byte content of the uploaded image file.

    Returns:
        A tuple of (success: bool, decoded_text: Optional[str], error_message: Optional[str])
    """
    try:
        # Convert raw bytes into a 1D NumPy array
        np_arr = np.frombuffer(image_bytes, np.uint8)

        # Decode the NumPy array into an OpenCV image (BGR format)
        image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        # Verify that the image was properly decoded
        if image is None:
            return False, None, "Could not decode image. The file may be corrupted or in an unsupported format."

        # Initialize OpenCV QR Code detector
        detector = cv2.QRCodeDetector()

        # Attempt to detect and decode the QR code
        decoded_text, points, _ = detector.detectAndDecode(image)

        # If standard detection produced no result, try pre-processing (grayscale + Otsu threshold)
        if not decoded_text:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            decoded_text, points, _ = detector.detectAndDecode(thresh)

        # If a QR code was successfully decoded and contains text
        if decoded_text and decoded_text.strip():
            return True, decoded_text.strip(), None
        else:
            return False, None, "No QR code could be detected in the provided image."

    except Exception as e:
        return False, None, f"An unexpected error occurred during QR decoding: {str(e)}"
