"""XAI-IDS frontend settings."""
import os

# Where the backend API is running (see backend/common/xai_ids/config.py)
BACKEND_URL = os.environ.get("XAI_IDS_BACKEND_URL", "http://127.0.0.1:5001").rstrip("/")

HOST = os.environ.get("XAI_IDS_FRONTEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("XAI_IDS_FRONTEND_PORT", 5000))
