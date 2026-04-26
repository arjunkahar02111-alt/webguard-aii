"""
WebGuard AI — Risk Scorer
Computes overall risk score and level from scan findings.
"""
from typing import List, Tuple, Dict

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}

SEVERITY_TO_RISK = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def compute_risk_score(findings: List[Dict]) -> Tuple[int, str]:
    """
    Returns (score 0-100, risk_level).
    Score 0 = most dangerous. Score 100 = secure.
    """
    if not findings:
        return 95, "LOW"

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_penalty = 0

    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        total_penalty += SEVERITY_WEIGHTS.get(sev, 0)

    # Cap penalty at 100
    score = max(0, 100 - min(total_penalty, 100))

    # Determine risk level
    if severity_counts["CRITICAL"] > 0 or score < 25:
        risk_level = "CRITICAL"
    elif severity_counts["HIGH"] >= 2 or score < 50:
        risk_level = "HIGH"
    elif severity_counts["MEDIUM"] >= 2 or score < 70:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level


def compute_cvss_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    if cvss > 0.0: return "LOW"
    return "INFO"
