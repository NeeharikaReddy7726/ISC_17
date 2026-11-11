"""
Generates a sample QR code image file for manual testing.
Run this script to create 'sample_qr.png' in the backend directory.
"""
import qrcode
import os

target_url = "https://example-university-portal.edu/student-login"

qr = qrcode.QRCode(
    version=1,
    box_size=10,
    border=4,
)
qr.add_data(target_url)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
output_path = os.path.join(os.path.dirname(__file__), "sample_qr.png")
img.save(output_path)

print(f"Sample QR code generated successfully at: {output_path}")
print(f"Encoded content: {target_url}")
