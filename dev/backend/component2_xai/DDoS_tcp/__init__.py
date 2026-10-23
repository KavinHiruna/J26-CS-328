"""DDoS TCP SYN Flood detection with explainable AI (Edge-IIoTset) — Component 2."""
from .service import DDoSTcpXAI, ModelNotTrainedError  # noqa: F401

__all__ = ["DDoSTcpXAI", "ModelNotTrainedError"]
