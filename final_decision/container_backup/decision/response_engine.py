def _build_context(
    normalized,
    risk,
    ml_result=None
):

    risk = risk or {}
    ml_result = ml_result or {}

    ml_analysis = (
        normalized.get(
            "ml_analysis",
            {}
        )
        or {}
    )

    return {

        "incident_id":
            normalized.get(
                "incident_id"
            ),

        "hostname":
            normalized.get(
                "hostname",
                "unknown"
            ),

        "incident_type":
            normalized.get(
                "incident_type",
                "unknown"
            ),

        "platform":
            normalized.get(
                "platform",
                "unknown"
            ),

        "rule_id":
            normalized.get(
                "rule_id"
            ),

        "rule_level":
            normalized.get(
                "rule_level"
            ),

        "description":
            normalized.get(
                "description"
            ),

        "confidence":
            (
                normalized.get(
                    "classification",
                    {}
                )
                or {}
            ).get(
                "confidence"
            ),

        "final_score":
            risk.get(
                "final_score",
                0
            ),

        "malicious_iocs":
            risk.get(
                "malicious_iocs",
                0
            ),

        "ips":
            normalized.get(
                "ioc",
                {}
            ).get(
                "ips",
                []
            ),

        "urls":
            normalized.get(
                "ioc",
                {}
            ).get(
                "urls",
                []
            ),

        "domains":
            normalized.get(
                "ioc",
                {}
            ).get(
                "domains",
                []
            ),

        "hashes":
            normalized.get(
                "ioc",
                {}
            ).get(
                "hashes",
                []
            ),

        "ml_available":
            ml_result.get(
                "available",
                False
            ),

        "ml_prediction":
            ml_result.get(
                "prediction"
            ),

        "ml_confidence":
            ml_result.get(
                "confidence"
            ),

        "ml_proba_true_positive":
            ml_result.get(
                "proba_true_positive"
            ),

        "ml_confidence_level":
            ml_result.get(
                "confidence_level"
            ),

        "ml_model_version":
            ml_result.get(
                "model_version"
            ),

        "ml_disagreement":
            ml_analysis.get(
                "disagreement",
                False
            ),

        "ml_disagreement_severity":
            ml_analysis.get(
                "severity",
                "NONE"
            ),

        "ml_learning_priority":
            ml_analysis.get(
                "learning_priority",
                0
            ),
                "zero_day_verdict":
            (
                normalized.get(
                    "zero_day_analysis",
                    {}
                )
                or {}
            ).get(
                "verdict",
                "NO_ANOMALY"
            ),

        "zero_day_score":
            (
                normalized.get(
                    "zero_day_analysis",
                    {}
                )
                or {}
            ).get(
                "score",
                0
            ),

        "zero_day_signals":
            (
                normalized.get(
                    "zero_day_analysis",
                    {}
                )
                or {}
            ).get(
                "signals",
                []
            ),

        "zero_day_novel_fleet_items":
            (
                normalized.get(
                    "zero_day_analysis",
                    {}
                )
                or {}
            ).get(
                "novel_fleet_items",
                0
            ),

        "ml_role":
            "ADVISORY_ONLY"
    }
import re

def _extract_ip_from_urls(urls):
  
    ip_pattern = re.compile(
        r"^https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )

    for url in (urls or []):
        match = ip_pattern.match(url)
        if match:
            return match.group(1)

    return None


def _build_targeted_actions(
    incident,
    platform,
    hostname,
    normalized,
    context
):

    actions = []

    ioc = (normalized.get("ioc", {}) or {})
    ips = ioc.get("ips", [])
    urls = ioc.get("urls", [])
    target_ip = ips[0] if ips else _extract_ip_from_urls(urls)

    if target_ip:

            actions.append({
                "tool": "velociraptor",
                "action": "run_artifact",
                "response": "BLOCK_IP",
                "target": hostname,
                "platform": platform,
                "parameters": {"IP": target_ip},
                "context": context
            })

    if incident == "Command and Control":

        if ips:

            actions.append({
                "tool": "velociraptor",
                "action": "run_artifact",
                "response": "BLOCK_IP",
                "target": hostname,
                "platform": platform,
                "parameters": {
                    "IP": ips[0]
                },
                "context": context
            })

    elif incident in (
        "Malware",
        "Trojan"
    ):

        actions.append({
            "tool": "velociraptor",
            "action": "run_artifact",
            "response": "DELETE_FILE",
            "target": hostname,
            "platform": platform,
            "context": context
        })

        actions.append({
            "tool": "velociraptor",
            "action": "run_artifact",
            "response": "KILL_PROCESS",
            "target": hostname,
            "platform": platform,
            "context": context
        })

    elif incident == "Ransomware":

        actions.append({
            "tool": "velociraptor",
            "action": "run_artifact",
            "response": "KILL_PROCESS",
            "target": hostname,
            "platform": platform,
            "context": context
        })

    elif incident == "Persistence":

        actions.append({
            "tool": "velociraptor",
            "action": "run_artifact",
            "response": "REMOVE_PERSISTENCE",
            "target": hostname,
            "platform": platform,
            "context": context
        })

    elif incident in (
        "Credential Access",
        "Execution"
    ):

        actions.append({
            "tool": "velociraptor",
            "action": "run_artifact",
            "response": "KILL_PROCESS",
            "target": hostname,
            "platform": platform,
            "context": context
        })

    return actions


def build_response(
    decision,
    normalized,
    risk=None,
    ml_result=None
):

    incident = normalized.get(
        "incident_type",
        ""
    )

    platform = normalized.get(
        "platform",
        "Linux"
    )

    hostname = normalized.get(
        "hostname",
        ""
    )

    context = _build_context(
        normalized,
        risk,
        ml_result
    )

    if decision == "FALSE_POSITIVE":

        return {
            "automatic": False,
            "analyst_approval_required": False,
            "actions": [
                {
                    "tool": "notification",
                    "action": "false_positive_candidate",
                    "context": context
                }
            ]
        }

    if decision == "KNOWN_FALSE_POSITIVE":

        return {
            "automatic": False,
            "analyst_approval_required": False,
            "actions": [
                {
                    "tool": "notification",
                    "action": "known_false_positive",
                    "context": context
                }
            ]
        }

    if decision == "KNOWN_TRUE_POSITIVE":

        return {
            "automatic": False,
            "analyst_approval_required": False,
            "actions": [
                {
                    "tool": "notification",
                    "action": "known_true_positive",
                    "context": context
                }
            ]
        }

    if decision == "MONITOR":

        return {
            "automatic": False,
            "analyst_approval_required": False,
            "actions": [
                {
                    "tool": "notification",
                    "action": "monitor",
                    "context": context
                }
            ]
        }

    if decision == "AUTO_CONTAIN":

        return {
            "automatic": False,
            "analyst_approval_required": True,
            "actions": [
                {
                    "tool": "notification",
                    "action": "critical_alert",
                    "context": context
                }
            ]
        }
    zero_day_verdict = (
        (normalized.get("zero_day_analysis", {}) or {}).get("verdict")
    )

    zero_day_critical = zero_day_verdict == "ZERO_DAY_CANDIDATE"

    if decision in (
            "ANALYST_APPROVAL",
            "AUTO_RESPONSE"
        ):

            actions = _build_targeted_actions(
                incident,
                platform,
                hostname,
                normalized,
                context
            )

            if zero_day_critical:
                notif_type = "zero_day_alert"
            elif decision == "AUTO_RESPONSE":
                notif_type = "critical_alert"
            else:
                notif_type = "analyst_review"

            actions.append({
                "tool": "notification",
                "action": notif_type,
                "context": context
            })

            return {
                "automatic": False,
                "analyst_approval_required": True,
                "actions": actions
            }

    return {
        "automatic": False,
        "analyst_approval_required": False,
        "actions": []
    }