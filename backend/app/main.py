from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.models import User, ScanHistory  # Ensure all models are registered with Base metadata
from app.routers import scanner, auth, history

# Create all database tables in SQLite on application startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="QR Shield API",
    description=(
        "Backend API for QR Shield - QR Code Security Scanner.\n\n"
        "Features:\n"
        "- Module 1: QR Code Image Decoding (OpenCV)\n"
        "- Module 2: AI-Powered Phishing URL Classification (Random Forest)\n"
        "- Module 3: User Authentication & Access Control (Argon2 + JWT)\n"
        "- Module 4: Cryptographic Security & Protected Scan History (SHA-256 + AES-256-GCM)"
    ),
    version="1.0.0"
)

# Configure CORS so our React frontend can communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(auth.router)
app.include_router(scanner.router)
app.include_router(history.router)


@app.get("/")
def root():
    return {
        "status": "online",
        "app": "QR Shield API",
        "version": "1.0.0",
        "docs_url": "/docs"
    }
