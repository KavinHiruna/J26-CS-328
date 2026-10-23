"""DDoS UDP Flood detection with explainable AI (Edge-IIoTset) — Component 2."""
from .service import DDoSUdpXAI, ModelNotTrainedError  # noqa: F401

__all__ = ["DDoSUdpXAI", "ModelNotTrainedError"]
