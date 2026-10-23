"""
scoring.py - the risk score and the priority level. This is the heart of Component 3.

    risk = 100 x ( w_sev x S + w_conf x C + w_asset x A + w_freq x F )

S, A and F run from 1 to 5 and are rescaled to 0..1 with (x - 1) / 4 (min-max normalisation).
C (confidence) is already a probability between 0 and 1.
"""
from .config import LEVEL_CUTOFFS, WEIGHTS

# Allowed range of each input. Anything outside is rejected, never "fixed" silently.
RANGES = {"severity": (1, 5), "confidence": (0, 1), "asset": (1, 5), "frequency": (1, 5)}


def scale(value, low, high):
    """Min-max scaling: the lowest value becomes 0 and the highest becomes 1."""
    return (value - low) / (high - low)


def check_inputs(severity, confidence, asset, frequency):
    """Stop with a clear message if a factor is missing, not a number, or out of range."""
    given = {"severity": severity, "confidence": confidence, "asset": asset, "frequency": frequency}
    for name, value in given.items():
        if value is None or isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
            raise ValueError(f"{name} must be a number (got {value!r}).")
        low, high = RANGES[name]
        if not low <= value <= high:
            raise ValueError(f"{name} must be between {low} and {high} (got {value}).")


def scaled_factors(severity, confidence, asset, frequency):
    """The four factors on the common 0..1 scale."""
    check_inputs(severity, confidence, asset, frequency)
    return {
        "severity": scale(severity, 1, 5),
        "confidence": confidence,
        "asset": scale(asset, 1, 5),
        "frequency": scale(frequency, 1, 5),
    }


def risk_score(severity, confidence, asset, frequency):
    """The 0-100 risk score, rounded to 2 decimals."""
    f = scaled_factors(severity, confidence, asset, frequency)
    total = (WEIGHTS["severity"] * f["severity"] + WEIGHTS["confidence"] * f["confidence"]
             + WEIGHTS["asset"] * f["asset"] + WEIGHTS["frequency"] * f["frequency"])
    return round(100 * total, 2)


def contributions(severity, confidence, asset, frequency):
    """How many points each factor adds to the 0-100 score. Use it to explain a score."""
    parts = scaled_factors(severity, confidence, asset, frequency)
    return {name: 100 * WEIGHTS[name] * parts[name] for name in parts}


def priority_level(score):
    """Critical / High / Medium / Low from the FIRST CVSS v3.1 bands (score / 10)."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100.")
    if score >= LEVEL_CUTOFFS["Critical"]:
        return "Critical"
    if score >= LEVEL_CUTOFFS["High"]:
        return "High"
    if score >= LEVEL_CUTOFFS["Medium"]:
        return "Medium"
    return "Low"


# ---- Advice shown with an alert (advisory only: a human analyst decides and approves any action) ----
LEVEL_ADVICE = {
    "Critical": ["Investigate the alert immediately", "Notify the SOC lead and OT administrator",
                 "Assess potential impact on the industrial process"],
    "High": ["Investigate the alert as soon as possible", "Notify the responsible security analyst",
             "Review related alerts and affected assets"],
    "Medium": ["Review the alert during the current triage cycle", "Check for related suspicious activity"],
    "Low": ["Record the alert for routine monitoring", "Review if additional suspicious activity appears"],
}
ATTACK_ADVICE = {
    "Ransomware": "Check for signs of encryption or disruption; consider containment through the approved OT procedure",
    "DDoS_UDP": "Check network availability, traffic volume, and affected services",
    "DDoS_ICMP": "Check network availability, traffic volume, and affected services",
    "DDoS_TCP": "Check network availability, traffic volume, and affected services",
    "DDoS_HTTP": "Review HTTP request rates and affected web services",
    "MITM": "Review communication integrity, endpoints, and network paths",
    "Backdoor": "Investigate suspicious remote access and persistence indicators",
    "SQL_injection": "Review application logs and database access for suspicious queries",
    "Password": "Review authentication logs and check for repeated failed logins",
    "Port_Scanning": "Review the source, target ports, and subsequent connection attempts",
    "Vulnerability_scanner": "Verify whether the scanning activity was authorized",
    "XSS": "Review web application logs and investigate possible injection activity",
    "Fingerprinting": "Review reconnaissance activity and exposed service information",
    "Uploading": "Review transferred files and verify whether the upload was authorized",
}


def recommend(level, attack_type):
    """Advisory steps for an alert: level-based first, then attack-specific."""
    if level not in LEVEL_ADVICE:
        raise ValueError("Unknown level. Use Critical, High, Medium or Low.")
    steps = list(LEVEL_ADVICE[level])
    if attack_type in ATTACK_ADVICE:
        steps.append(ATTACK_ADVICE[attack_type])
    return steps
