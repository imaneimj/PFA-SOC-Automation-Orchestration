from taxonomy import (
    INCIDENT_TYPES,
    MITRE_MAPPING,
    TECHNIQUE_MAPPING,
    GROUP_MAPPING,
    DECODER_MAPPING,
    DESCRIPTION_KEYWORDS
)
def calculate_severity(rule_level):
    if rule_level >= 12:
        return "Critical"
    elif rule_level >= 8:
        return "High"
    elif rule_level >= 5:
        return "Medium"
    else:
        return "Low"
def classify(alert):
    print("\n========== CLASSIFIER ==========")
    incident_type = None
    confidence = 0
    source = None
    platform = alert.get("platform","Unknown")
    os_name = alert.get( "agent_os", "Unknown")
    rule_level = alert.get("rule_level", 0)
    severity = calculate_severity( rule_level)
    mitre = alert.get("mitre",{})
    tactics = mitre.get( "tactic", [])
    if isinstance(tactics,str):
        tactics=[tactics]
    print("MITRE :", tactics)
    techniques = mitre.get("technique",[])
    if isinstance(techniques, str):
        techniques = [techniques]
    print("MITRE Techniques :", techniques)
    for technique in techniques:
        if technique in TECHNIQUE_MAPPING:
            incident_type = TECHNIQUE_MAPPING[technique]
            confidence = 0.95
            source = "MITRE Technique"
            break
    if not incident_type:
        for tactic in tactics:
                    if tactic in MITRE_MAPPING:
                        incident_type = MITRE_MAPPING[tactic]
                        confidence = 0.90
                        source = "MITRE Tactic"
                        break
        groups = alert.get(
            "groups",
            []
        )
        print("GROUPS :", groups)
        for group in groups:
            if group in GROUP_MAPPING:
                incident_type = GROUP_MAPPING[group]
                confidence = 0.85
                source = "GROUP"
                break
    if not incident_type:
        decoder = alert.get( "decoder", "" )
        print("DECODER :", decoder)
        if decoder in DECODER_MAPPING:
            incident_type = DECODER_MAPPING[decoder]
            confidence = 0.75
            source = "DECODER"
    if not incident_type:
        description = alert.get("description","").lower()
        for keyword, incident in DESCRIPTION_KEYWORDS.items():
            if keyword in description:
                incident_type = incident
                confidence = 0.60
                source = "DESCRIPTION"
                break
    if not incident_type:
        incident_type = INCIDENT_TYPES["OTHER"]
        confidence = 0.30
        source = "DEFAULT"
    result = {
        "type": incident_type,
        "confidence": confidence,
        "severity": severity,
        "source": source,
        "platform": platform,
        "os": os_name}
    print(f"[RESULT] {incident_type}")
    print(f"[CONFIDENCE] {confidence}")
    print( f"[SEVERITY] {severity}")
    print("================================\n")
    return result