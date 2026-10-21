
"""
Initial attack severity mapping for the SOC prioritization prototype.

These are provisional research-design assumptions, not severity labels
provided by the Edge-IIoTset dataset. Review and justify them using
research literature and supervisor guidance before final evaluation.
"""

ATTACK_SEVERITY = {
    "DDoS_UDP": 4,
    "DDoS_ICMP": 4,
    "DDoS_HTTP": 4,
    "DDoS_TCP": 4,
    "Ransomware": 5,
    "Backdoor": 5,
    "MITM": 5,
    "SQL_injection": 4,
    "Uploading": 3,
    "Password": 3,
    "Port_Scanning": 2,
    "Vulnerability_scanner": 2,
    "XSS": 3,
    "Fingerprinting": 1,
}

SEVERITY_SCALE = {
    1: "Very Low",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Very High",
}


def get_attack_severity(attack_type):
    """Return a provisional severity score from 1 to 5."""
    return ATTACK_SEVERITY.get(attack_type)


if __name__ == "__main__":
    print("Provisional Attack Severity Mapping")
    print("-" * 45)

    for attack_type, score in ATTACK_SEVERITY.items():
        print(
            f"{attack_type:25} "
            f"Score: {score} "
            f"({SEVERITY_SCALE[score]})"
        )

    print("\nNumber of mapped attack types:", len(ATTACK_SEVERITY))
