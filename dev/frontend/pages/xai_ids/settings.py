"""XAI-IDS frontend settings."""
import os

# Where the backend API is running (see backend/common/xai_ids/config.py)
BACKEND_URL = os.environ.get("XAI_IDS_BACKEND_URL", "http://127.0.0.1:5001").rstrip("/")

HOST = os.environ.get("XAI_IDS_FRONTEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("XAI_IDS_FRONTEND_PORT", 5000))

# Where the SQL Injection XAI Streamlit page is running (linked from SQL injection incidents)
SQLI_XAI_URL = os.environ.get("SQLI_XAI_URL", "http://localhost:8501").rstrip("/")
