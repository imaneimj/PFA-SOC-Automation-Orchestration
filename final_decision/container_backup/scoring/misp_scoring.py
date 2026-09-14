from typing import Dict, List


def compute_misp_score(misp_results: List[dict]) -> Dict:
    """
    Calcule un score de risque à partir des résultats MISP.

    Correctif : le score par attribut n'est plus un flat +5 peu importe
    sa fiabilité. On pondère désormais selon :
      - to_ids (l'attribut est marqué comme utilisable en détection)
      - le threat_level de l'événement parent

    Un IOC n'est compté comme "confirmed_malicious" (utilisé par le
    Decision Engine) que si l'attribut a to_ids=True ET appartient à un
    événement threat_level High ou Critical.
    """

    score = 0
    reasons = []

    statistics = {
        "events": 0,
        "attributes": 0,
        "published_events": 0,
        "ioc_matches": 0,
        "confirmed_malicious": 0
    }

    if not misp_results:
        return {
            "score": 0,
            "risk": "LOW",
            "statistics": statistics,
            "reasons": []
        }

    confirmed_malicious_values = set()

    for response in misp_results:

        if not response.get("success", False):
            continue

        body = response.get("body", {})
        events = body.get("response", [])

        statistics["events"] += len(events)

        for event_wrapper in events:

            event = event_wrapper.get("Event", {})

            ################################################################
            # Threat Level
            ################################################################

            threat = int(event.get("threat_level_id", 4))

            if threat == 1:
                score += 40
                reasons.append("Threat level : High")
            elif threat == 2:
                score += 30
                reasons.append("Threat level : Medium")
            elif threat == 3:
                score += 15
                reasons.append("Threat level : Low")

            ################################################################
            # Event publié
            ################################################################

            if event.get("published", False):
                score += 15
                statistics["published_events"] += 1
                reasons.append("Published event")

            ################################################################
            # IOC présents — pondérés par to_ids + threat_level
            ################################################################

            attributes = event.get("Attribute", [])

            statistics["attributes"] += len(attributes)
            statistics["ioc_matches"] += len(attributes)

            for attr in attributes:

                value = attr.get("value", "")
                attr_type = attr.get("type", "")
                to_ids = attr.get("to_ids", False)

                if to_ids and threat <= 2:
                    # Attribut fiable, sur un événement à threat_level
                    # élevé : contribution significative + confirmé.
                    attr_score = 10
                    confirmed_malicious_values.add(value)
                elif to_ids:
                    # Attribut fiable, mais événement moins critique.
                    attr_score = 5
                else:
                    # to_ids=False : souvent contextuel/informatif,
                    # pas destiné à la détection. Contribution minime.
                    attr_score = 1

                score += attr_score

                reasons.append(
                    f"MISP match : {attr_type} -> {value} "
                    f"(to_ids={to_ids})"
                )

    ####################################################################
    # Limitation
    ####################################################################

    score = min(score, 100)

    ####################################################################
    # Niveau de risque
    ####################################################################

    if score >= 80:
        risk = "CRITICAL"
    elif score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    statistics["confirmed_malicious"] = len(confirmed_malicious_values)

    return {
        "score": score,
        "risk": risk,
        "statistics": statistics,
        "reasons": reasons
    }