import hashlib
import re
from typing import Any,Dict

def _safe(value):
    if value is None:
        return ""
    if isinstance(value,(dict,list,tuple,set)):
        return str(value).strip().lower()
    return str(value).strip().lower()

def _safe_dict(value):
    if isinstance(value,dict):
        return value
    return {}

def normalize_command(command):
    command=_safe(command)

    if not command:
        return ""

    command=re.sub(
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        "<IP>",
        command
    )

    command=re.sub(
        r"https?://[^\s\"']+",
        "<URL>",
        command,
        flags=re.IGNORECASE
    )

    command=re.sub(
        r"\b[A-Za-z0-9+/]{20,}={0,2}\b",
        "<BASE64>",
        command
    )

    command=re.sub(
        r"\b[a-fA-F0-9]{32,64}\b",
        "<HASH>",
        command
    )

    command=re.sub(
        r"\b"
        r"[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}"
        r"\b",
        "<UUID>",
        command
    )

    command=re.sub(
        r"(/tmp/|/var/tmp/|"
        r"[A-Za-z]:[\\/]+Windows[\\/]+Temp[\\/]+)"
        r"[\w.\-]+",
        r"\1<TMPFILE>",
        command,
        flags=re.IGNORECASE
    )

    command=re.sub(
        r"((?:/home/|/users/|"
        r"[A-Za-z]:[\\/]+Users[\\/]+)"
        r"[^\\/\\s]+)",
        lambda m:re.sub(
            r"[^\\/]+$",
            "<USER>",
            m.group(1)
        ),
        command,
        flags=re.IGNORECASE
    )

    command=re.sub(
        r"\b\d{4,}\b",
        "<NUMBER>",
        command
    )

    command=re.sub(
        r"\s+",
        " ",
        command
    )

    return command.strip()

def _extract_process(normalized):
    normalized=_safe_dict(normalized)

    process=_safe_dict(
        normalized.get("process")
        if isinstance(normalized.get("process"),dict)
        else normalized.get("process_analysis")
    )

    process_name=(
        process.get("name")
        or process.get("process_name")
        or normalized.get("process_name")
        or normalized.get("image")
        or ""
    )

    parent_process=(
        process.get("parent")
        or process.get("parent_process")
        or process.get("parent_name")
        or normalized.get("parent_process")
        or normalized.get("parent_process_name")
        or ""
    )

    command=(
        process.get("command")
        or process.get("cmdline")
        or process.get("command_line")
        or normalized.get("command")
        or normalized.get("cmdline")
        or normalized.get("command_line")
        or ""
    )

    return {
        "process_name":_safe(process_name),
        "parent_process":_safe(parent_process),
        "command":command,
        "command_pattern":normalize_command(command)
    }

def _extract_network(normalized):
    normalized=_safe_dict(normalized)

    network=_safe_dict(
        normalized.get("network")
        if isinstance(normalized.get("network"),dict)
        else normalized.get("network_analysis")
    )

    destination=(
        network.get("destination")
        or network.get("dst_ip")
        or network.get("destination_ip")
        or network.get("remote_ip")
        or normalized.get("destination")
        or normalized.get("dst_ip")
        or normalized.get("destination_ip")
        or normalized.get("remote_ip")
        or ""
    )

    destination_domain=(
        network.get("domain")
        or network.get("destination_domain")
        or network.get("remote_domain")
        or normalized.get("destination_domain")
        or normalized.get("domain")
        or ""
    )

    raw_port=(
        network.get("port")
        or network.get("destination_port")
        or normalized.get("destination_port")
        or normalized.get("dst_port")
    )

    if raw_port in (None,""):
        port=-1
    else:
        try:
            port=int(raw_port)
        except (TypeError,ValueError):
            port=-1

    protocol=(
        network.get("protocol")
        or normalized.get("protocol")
        or ""
    )

    destination_value=(
        destination
        if destination
        else destination_domain
    )

    return {
        "destination":_safe(destination_value),
        "destination_port":port,
        "protocol":_safe(protocol)
    }

def build_behavior_fingerprint(normalized:Dict[str,Any])->Dict[str,Any]:
    normalized=_safe_dict(normalized)
    process=_extract_process(normalized)
    network=_extract_network(normalized)

    raw_components=[
        process["process_name"],
        process["parent_process"],
        process["command_pattern"],
        network["destination"],
        _safe(network["destination_port"]),
        network["protocol"]
    ]

    raw="|".join(raw_components)
    fingerprint=hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()

    return {
        "fingerprint":fingerprint,
        "process_name":process["process_name"],
        "parent_process":process["parent_process"],
        "command_pattern":process["command_pattern"],
        "destination":network["destination"],
        "destination_port":network["destination_port"],
        "protocol":network["protocol"],
        "raw":raw
    }