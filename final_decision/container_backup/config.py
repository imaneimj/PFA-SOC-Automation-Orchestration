"""
Configuration du Final Decision Engine

Source unique de vérité pour les pondérations,
seuils de décision, garde-fous et configuration Zero-Day.
"""

# ==========================================================
# Pondérations des sources de scoring
# ==========================================================

SOURCE_WEIGHTS = {
    "decision_engine": 0.45,
    "misp": 0.30,
    "cortex": 0.25
}

# ==========================================================
# Seuils de décision
# ==========================================================

DECISION_THRESHOLDS = {
    "auto_contain": 85,
    "auto_response": 80,
    "analyst_approval": 60,
    "monitor": 40
}

# ==========================================================
# Types d'incidents éligibles à AUTO_CONTAIN
# ==========================================================

AUTO_CONTAIN_INCIDENT_TYPES = [
    "Malware",
    "Trojan",
    "Ransomware",
    "Command and Control"
]

# ==========================================================
# IOC malveillants minimum
# ==========================================================

MIN_MALICIOUS_IOCS_AUTO_CONTAIN = 2

MIN_MALICIOUS_IOCS_AUTO_RESPONSE = 1

# ==========================================================
# Ransomware
# ==========================================================

RANSOMWARE_BYPASS_SCORE_THRESHOLD = True

# ==========================================================
# Zero-Day
# ==========================================================

ZERO_DAY_BASELINE = {

    # Phase d'apprentissage
    "learning_min_events": 20,

    # Phase mature
    "mature_min_events": 100,

    # Nombre d'occurrences nécessaires pour considérer
    # un comportement comme établi
    "established_behavior_occurrences": 3,

    # Réduction du score pendant l'apprentissage
    "learning_score_multiplier": 0.60,

    # Réduction du score pour un comportement faible
    "weak_score_multiplier": 0.85,

    # Bonus lorsqu'un comportement est mature
    "mature_bonus": 5,

    # Score minimum permettant un blocage pendant
    # la phase d'apprentissage
    "block_learning_score": 60
}