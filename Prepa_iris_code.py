import json

raw = '''$final_decision.body'''

data = json.loads(raw)

risk = data.get("risk", {})
decision_data = data.get("decision", {})
ml_data = data.get("ml", {})
ml_result = ml_data.get("result", {})
response = data.get("response", {})

context = {}

actions = response.get("actions", [])

if actions:
    context = actions[0].get("context", {})

incident_id = (
    context.get("incident_id")
    or data.get("db", {}).get("incident_id")
    or ""
)

hostname = context.get("hostname", "")
incident_type = context.get("incident_type", "")
rule_id = str(context.get("rule_id", ""))
description = context.get("description", "")
platform = context.get("platform", "Linux")

rule_level = context.get("rule_level")
confidence = context.get("confidence")

iocs = {
    "ips": context.get("ips", []),
    "domains": context.get("domains", []),
    "urls": context.get("urls", []),
    "hashes": context.get("hashes", [])
}

output = {
    "incident_id": incident_id,
    "alert_id": incident_id,

    "hostname": hostname,
    "platform": platform,

    "rule_id": rule_id,
    "rule_level": rule_level,

    "incident_type": incident_type,
    "description": description,

    "severity": "High",
    "risk": decision_data.get(
        "risk",
        "Unknown"
    ),

    "final_score": risk.get(
        "final_score",
        0
    ),

    "decision": decision_data.get(
        "decision",
        "UNKNOWN"
    ),

    "confidence": confidence,

    "iocs": iocs,

    "malicious_iocs": risk.get(
        "malicious_iocs",
        0
    ),

    "decision_engine_score": risk.get(
        "decision_engine",
        {}
    ).get("score", 0),

    "misp_score": risk.get(
        "misp",
        {}
    ).get("score", 0),

    "cortex_score": risk.get(
        "cortex",
        {}
    ).get("score", 0),

    "ml": {
        "prediction": ml_result.get("prediction"),
        "confidence": ml_result.get("confidence"),
        "confidence_level": ml_result.get("confidence_level"),
        "model_version": ml_result.get("model_version")
    },

    "response_required": decision_data.get(
        "response_required",
        False
    ),

    "analyst_approval_required": decision_data.get(
        "analyst_approval_required",
        False
    ),

    "response": response,

    "source": "Wazuh"
}

print(json.dumps(output))