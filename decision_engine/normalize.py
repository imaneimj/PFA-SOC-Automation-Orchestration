from evidence_processor import extract_wazuh_iocs
def normalize(alert):
    all_fields = alert.get("all_fields", {})
    agent = all_fields.get("agent", {})
    rule = all_fields.get("rule", {})
    decoder = all_fields.get("decoder", {})
    predecoder = all_fields.get("predecoder", {})
    win = all_fields.get("win", {})
    eventdata = win.get("eventdata", {})
    network = all_fields.get("network", {})
    data_field = all_fields.get("data", {})
    ioc = extract_wazuh_iocs(all_fields)
    mitre = rule.get("mitre", {})
    if not isinstance(mitre, dict):
        mitre = {}
    normalized = {
        "incident_id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "hostname": agent.get("name", ""),
        "agent_id": agent.get("id", ""),
        "agent_ip": agent.get("ip", ""),
        "agent_os": agent.get("os", {}).get("name", ""),
        "agent_os_version": agent.get("os", {}).get("version", ""),
        "agent_architecture": agent.get("os", {}).get("architecture", ""),
        "rule_id": rule.get("id", ""),
        "rule_level": int(rule.get("level", 0)),
        "rule_firedtimes": rule.get("firedtimes", 1),
        "description": rule.get("description", ""),
        "groups": rule.get("groups", []),
        "mitre": mitre,
        "decoder": decoder.get("name", ""),
        "program": predecoder.get("program_name", ""),
        "username": eventdata.get("TargetUserName", data_field.get("dstuser", "")),
        "domain": eventdata.get("TargetDomainName", ""),
        "process_name": eventdata.get("Image", data_field.get("process_name", "")),
        "process_id": eventdata.get("ProcessId", ""),
        "parent_process": eventdata.get("ParentImage", ""),
        "command_line": eventdata.get("CommandLine", ""),
        "source_ip": network.get("srcip", data_field.get("srcip", "")),
        "destination_ip": network.get("dstip", data_field.get("dstip", "")),
        "source_port": network.get("srcport", ""),
        "destination_port": network.get("dstport", ""),
        "protocol": network.get("protocol", ""),
        "ioc": ioc,
        "full_log": all_fields.get("full_log", ""),
        "syscheck": all_fields.get("syscheck", {})}
    return normalized