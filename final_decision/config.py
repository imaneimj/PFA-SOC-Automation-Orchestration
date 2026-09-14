SOURCE_WEIGHTS = {
    "decision_engine": 0.40,
    "misp": 0.25,
    "cortex": 0.20,
    "zero_day": 0.15
}

ZERO_DAY_BASELINE = {

    "learning_min_events": 20,
    "mature_min_events": 100,

    "established_behavior_occurrences": 3,

    "learning_score_multiplier": 0.60,
    "weak_score_multiplier": 0.85,

    "mature_bonus": 5,

    "block_learning_score": 60,
    "safe_learning_max_score": 25,
    "min_distinct_days_before_trust": 3
}

DECISION_THRESHOLDS = {
    "auto_contain": 75,
    "auto_response": 60,
    "monitor": 40
}
AUTO_CONTAIN_INCIDENT_TYPES = [
    "Malware",
    "Trojan",
    "Ransomware",
    "Command and Control"
]
MIN_MALICIOUS_IOCS_AUTO_CONTAIN = 2
MIN_MALICIOUS_IOCS_AUTO_RESPONSE = 1
RANSOMWARE_BYPASS_SCORE_THRESHOLD = True

