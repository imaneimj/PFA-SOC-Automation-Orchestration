from config import (
    DECISION_THRESHOLDS,
    AUTO_CONTAIN_INCIDENT_TYPES,
    MIN_MALICIOUS_IOCS_AUTO_CONTAIN,
    MIN_MALICIOUS_IOCS_AUTO_RESPONSE,
    RANSOMWARE_BYPASS_SCORE_THRESHOLD,
    ZERO_DAY_FORCE_VERDICTS,
    ZERO_DAY_MIN_NOVEL_FLEET_ITEMS
)


def _decision(decision, risk, zero_day_verdict, novel_fleet_items, zero_day_escalated=False):
    response_required = decision not in ("FALSE_POSITIVE", "MONITOR")
    return {
        "decision": decision,
        "risk": risk,
        "response_required": response_required,
        "analyst_approval_required": response_required,
        "zero_day_verdict": zero_day_verdict,
        "zero_day_novel_items": novel_fleet_items,
        "zero_day_escalated": zero_day_escalated
    }


def make_decision(
    final_score,
    incident_type="",
    malicious_iocs=0,
    zero_day=None
):

    final_score = float(final_score or 0)
    malicious_iocs = int(malicious_iocs or 0)
    incident_type = (incident_type or "").strip()
    zero_day = zero_day or {}

    zero_day_verdict = zero_day.get("verdict", "NO_ANOMALY")
    novel_fleet_items = int(zero_day.get("novel_fleet_items", 0) or 0)

    zero_day_forced = (
        zero_day_verdict in ZERO_DAY_FORCE_VERDICTS
        and novel_fleet_items >= ZERO_DAY_MIN_NOVEL_FLEET_ITEMS
    )

    is_high_impact = incident_type in AUTO_CONTAIN_INCIDENT_TYPES

    ransomware_bypass = (
        incident_type == "Ransomware"
        and malicious_iocs >= MIN_MALICIOUS_IOCS_AUTO_CONTAIN
        and final_score >= RANSOMWARE_BYPASS_SCORE_THRESHOLD
    )

    if (
        (
            is_high_impact
            and malicious_iocs >= MIN_MALICIOUS_IOCS_AUTO_CONTAIN
            and final_score >= DECISION_THRESHOLDS["auto_contain"]
        )
        or ransomware_bypass
    ):
        return _decision("AUTO_CONTAIN", "Critical", zero_day_verdict, novel_fleet_items)

    if (
        final_score >= DECISION_THRESHOLDS["auto_response"]
        and malicious_iocs >= MIN_MALICIOUS_IOCS_AUTO_RESPONSE
    ):
        return _decision("AUTO_RESPONSE", "High", zero_day_verdict, novel_fleet_items)

    if final_score >= DECISION_THRESHOLDS["auto_response"]:
        return _decision("ANALYST_APPROVAL", "High", zero_day_verdict, novel_fleet_items)

    if final_score >= DECISION_THRESHOLDS["analyst_approval"]:
        return _decision("ANALYST_APPROVAL", "High", zero_day_verdict, novel_fleet_items)

    if zero_day_forced:
        # Le score composite seul dirait MONITOR ou FALSE_POSITIVE, mais
        # des preuves comportementales JAMAIS observées dans tout le parc
        # ont été détectées. On ne classe jamais ça silencieusement :
        # un analyste doit trancher.
        return _decision(
            "ANALYST_APPROVAL", "Critical",
            zero_day_verdict, novel_fleet_items,
            zero_day_escalated=True
        )

    if final_score >= DECISION_THRESHOLDS["monitor"]:
        return _decision("MONITOR", "Medium", zero_day_verdict, novel_fleet_items)

    return _decision("FALSE_POSITIVE", "Low", zero_day_verdict, novel_fleet_items)