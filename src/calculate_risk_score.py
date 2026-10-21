
def calculate_risk_score(
    attack_severity,
    detection_confidence,
    asset_criticality,
    attack_frequency,
):
    """
    Calculate a provisional SOC risk score from 0 to 100.

    Scales:
      attack_severity:       1 to 5
      detection_confidence:  0 to 1
      asset_criticality:     1 to 5
      attack_frequency:      1 to 5

    The AHP weights are provisional and must be validated.
    """

    # Normalize all factors to a 0–1 range
    severity = (attack_severity - 1) / 4
    confidence = detection_confidence
    criticality = (asset_criticality - 1) / 4
    frequency = (attack_frequency - 1) / 4

    # Provisional AHP weights from the previous script
    risk_score = 100 * (
        0.2628 * severity
        + 0.1409 * confidence
        + 0.4554 * criticality
        + 0.1409 * frequency
    )

    return round(risk_score, 2)


def classify_priority(score):
    """Classify a score using provisional thresholds."""

    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


if __name__ == "__main__":
    # Demonstration scenario only.
    # These values are illustrative, not measured dataset values.
    score = calculate_risk_score(
        attack_severity=5,
        detection_confidence=0.90,
        asset_criticality=5,
        attack_frequency=4,
    )

    print("SOC Risk Score Demonstration")
    print("----------------------------")
    print(f"Risk Score: {score}/100")
    print(f"Priority: {classify_priority(score)}")
