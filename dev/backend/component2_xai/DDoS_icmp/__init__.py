"""
Component 2 - Explainable AI for DDoS ICMP Flood detection (Edge-IIoTset).

Public API used by  frontend/pages/com2_attack/ddos_icmp.py
"""
from .config import (ATTACK_NAME, COMPONENT2_NOVELTY, COMPONENT2_NOVELTY_TITLE, DEFAULT_MODEL_PATH,
                     DOMAIN_RULES, FEATURE_SPECS, MODEL_FEATURES, SPEC_BY_NAME, ExplainSettings, pretty)
from .demo_data import make_demo_dataset
from .explain import Attribution, background_sample
from .features import FeatureReport, build_features
from .incident import (SEARCH_HELP, build_incident, incident_options, incident_to_json, incident_to_markdown,
                       score, search_incidents)
from .model import ModelAdapter, save_bundle, train_model
from .incident import benign_reference_from_scores
from .novelty import benign_reference

__all__ = [
    "ATTACK_NAME", "COMPONENT2_NOVELTY", "COMPONENT2_NOVELTY_TITLE", "DEFAULT_MODEL_PATH", "DOMAIN_RULES",
    "FEATURE_SPECS", "MODEL_FEATURES", "SPEC_BY_NAME", "ExplainSettings", "pretty", "make_demo_dataset",
    "Attribution", "background_sample", "FeatureReport", "build_features", "SEARCH_HELP", "build_incident",
    "incident_options", "incident_to_json", "incident_to_markdown", "score", "search_incidents",
    "ModelAdapter", "save_bundle", "train_model", "benign_reference", "benign_reference_from_scores",
]
