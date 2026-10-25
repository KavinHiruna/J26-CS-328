"""XAI-IDS frontend settings."""
import os

# Where the backend API is running (see backend/common/xai_ids/config.py)
BACKEND_URL = os.environ.get("XAI_IDS_BACKEND_URL", "http://192.168.1.119:5001").rstrip("/")

HOST = os.environ.get("XAI_IDS_FRONTEND_HOST", "0.0.0.0")
PORT = int(os.environ.get("XAI_IDS_FRONTEND_PORT", 5000))

# Where the Web Injection XAI Streamlit page (SQLi · XSS · Upload) is running (linked from those incidents)
SQLI_XAI_URL = os.environ.get("SQLI_XAI_URL", "http://192.168.1.119:8501").rstrip("/")

# Where the DDoS HTTP Flood XAI Streamlit page is running (linked from DDoS HTTP Flood incidents)
DDOS_XAI_URL = os.environ.get("DDOS_XAI_URL", "http://192.168.1.119:8503").rstrip("/")

# Where the DDoS Network Flood XAI page (network_flood.py: TCP SYN · UDP · ICMP) is running
ICMP_XAI_URL = os.environ.get("ICMP_XAI_URL", "http://192.168.1.119:8502").rstrip("/")
