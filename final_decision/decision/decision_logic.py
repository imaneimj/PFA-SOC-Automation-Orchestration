from config import (
    DECISION_THRESHOLDS,
    AUTO_CONTAIN_INCIDENT_TYPES,
    MIN_MALICIOUS_IOCS_AUTO_CONTAIN,
    MIN_MALICIOUS_IOCS_AUTO_RESPONSE,
    RANSOMWARE_BYPASS_SCORE_THRESHOLD
)

def make_decision(final_score,incident_type="",malicious_iocs=0):
    final_score=float(final_score or 0)
    malicious_iocs=int(malicious_iocs or 0)
    incident_type=(incident_type or "").strip()
    is_high_impact=incident_type in AUTO_CONTAIN_INCIDENT_TYPES

    if (
        is_high_impact
        and malicious_iocs>=MIN_MALICIOUS_IOCS_AUTO_CONTAIN
        and final_score>=DECISION_THRESHOLDS["auto_contain"]
    ):
        return {
            "decision":"AUTO_CONTAIN",
            "risk":"Critical",
            "response_required":True,
            "analyst_approval_required":True
        }

    if (
        RANSOMWARE_BYPASS_SCORE_THRESHOLD
        and incident_type=="Ransomware"
        and malicious_iocs>=MIN_MALICIOUS_IOCS_AUTO_CONTAIN
    ):
        return {
            "decision":"AUTO_CONTAIN",
            "risk":"Critical",
            "response_required":True,
            "analyst_approval_required":True
        }

    if (
        final_score>=DECISION_THRESHOLDS["auto_response"]
        and malicious_iocs>=MIN_MALICIOUS_IOCS_AUTO_RESPONSE
    ):
        return {
            "decision":"AUTO_RESPONSE",
            "risk":"High",
            "response_required":True,
            "analyst_approval_required":True
        }

    if final_score>=DECISION_THRESHOLDS["monitor"]:
        return {
            "decision":"MONITOR",
            "risk":"Medium",
            "response_required":False,
            "analyst_approval_required":False
        }

    return {
        "decision":"FALSE_POSITIVE",
        "risk":"Low",
        "response_required":False,
        "analyst_approval_required":False
    }