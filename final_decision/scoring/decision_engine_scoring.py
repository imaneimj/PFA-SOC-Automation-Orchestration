SEVERITY_SCORE = {
    "Critical": 40,
    "High": 30,
    "Medium": 20,
    "Low": 10,
    "Unknown": 0
}

PRIORITY_SCORE = {
    "Critical": 20,
    "High": 15,
    "Medium": 10,
    "Low": 5,
    "Unknown": 0
}

def score_decision_engine(decision_engine):
    score = 0
    details = {}
    severity = decision_engine.get("classification", {}).get("severity", "Unknown")
    severity_score = SEVERITY_SCORE.get(severity, 0)
    score += severity_score
    details["severity"] = {
        "value": severity,
        "score": severity_score}
    rule_level = decision_engine.get("rule_level", 0)
    rule_score = min(rule_level * 2, 20)
    score += rule_score
    details["rule_level"] = {
        "value": rule_level,
        "score": rule_score}
    confidence = decision_engine.get("classification", {}).get("confidence", 0)
    confidence_score = int(confidence * 10)
    score += confidence_score
    details["confidence"] = {
        "value": confidence,
        "score": confidence_score}
    priority = decision_engine.get("investigation_plan", {}).get("priority", "Unknown")
    priority_score = PRIORITY_SCORE.get(priority, 0)
    score += priority_score
    details["priority"] = {
        "value": priority,
        "score": priority_score}
    total_iocs = decision_engine.get("ioc_statistics", {}).get("total", 0)
    ioc_score = min(total_iocs * 5, 20)
    score += ioc_score
    details["ioc_statistics"] = {
        "total": total_iocs,
        "score": ioc_score}
    score = min(score, 100)
    return {
        "score": score,
        "details": details
    }