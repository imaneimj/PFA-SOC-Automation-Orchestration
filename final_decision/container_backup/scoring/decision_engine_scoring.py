# scoring/decision_engine_scoring.py

SEVERITY_SCORE = {
    "Critical": 40,
    "High": 30,
    "Medium": 20,
    "Low": 10,
    "Unknown": 0
}
ZERO_DAY_VERDICT_SCORE = {
    "ZERO_DAY_CANDIDATE": 25,
    "UNKNOWN_THREAT": 18,
    "SUSPICIOUS": 10,
    "LOW_CONFIDENCE_ANOMALY": 5,
    "NO_ANOMALY": 0,
}

PRIORITY_SCORE = {
    "Critical": 20,
    "High": 15,
    "Medium": 10,
    "Low": 5,
    "Unknown": 0
}


def score_decision_engine(decision_engine):
    """
    Calcule un score à partir des résultats du Decision Engine.
    """

    score = 0

    details = {}

    # -------------------------
    # Severity
    # -------------------------
    severity = (
        decision_engine
        .get("classification", {})
        .get("severity", "Unknown")
    )

    severity_score = SEVERITY_SCORE.get(severity, 0)

    score += severity_score

    details["severity"] = {
        "value": severity,
        "score": severity_score
    }

    # -------------------------
    # Rule Level
    # -------------------------
    rule_level = decision_engine.get("rule_level", 0)

    rule_score = min(rule_level * 2, 20)

    score += rule_score

    details["rule_level"] = {
        "value": rule_level,
        "score": rule_score
    }

    # -------------------------
    # Confidence
    # -------------------------
    confidence = (
        decision_engine
        .get("classification", {})
        .get("confidence", 0)
    )

    confidence_score = int(confidence * 10)

    score += confidence_score

    details["confidence"] = {
        "value": confidence,
        "score": confidence_score
    }

    # -------------------------
    # Priority
    # -------------------------
    priority = (
        decision_engine
        .get("investigation_plan", {})
        .get("priority", "Unknown")
    )

    priority_score = PRIORITY_SCORE.get(priority, 0)

    score += priority_score

    details["priority"] = {
        "value": priority,
        "score": priority_score
    }

    # -------------------------
    # IOC Statistics
    # -------------------------
    total_iocs = (
        decision_engine
        .get("ioc_statistics", {})
        .get("total", 0)
    )

    ioc_score = min(total_iocs * 5, 20)

    score += ioc_score

    details["ioc_statistics"] = {
        "total": total_iocs,
        "score": ioc_score
    }
        # -------------------------
    # Zero-Day behavioral signal
    # -------------------------
    zero_day = decision_engine.get("zero_day_analysis", {}) or {}
    zero_day_verdict = zero_day.get("verdict", "NO_ANOMALY")

    zero_day_score = ZERO_DAY_VERDICT_SCORE.get(zero_day_verdict, 0)

    score += zero_day_score

    details["zero_day"] = {
        "verdict": zero_day_verdict,
        "novel_fleet_items": zero_day.get("novel_fleet_items", 0),
        "score": zero_day_score
    }
    # -------------------------
    # Limitation
    # -------------------------
    score = min(score, 100)

    return {

        "score": score,

        "details": details
    }