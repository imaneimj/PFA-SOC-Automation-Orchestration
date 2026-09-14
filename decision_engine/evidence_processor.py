import re
import ipaddress
from datetime import datetime, timedelta
from ioc_rules import HIGH_RISK_PROCESSES, USELESS_HASHES
from analysis_rules import SECURITY_TOOLS

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def is_valid_hash(value):
    if not value:
        return False
    value = str(value).lower().strip()
    if value in USELESS_HASHES:
        return False
    return len(value) in (32, 40, 64) and re.match(r"^[a-f0-9]+$", value)

def clean_iocs(iocs):
    for key in iocs:
        iocs[key] = list(set(iocs[key]))
    return iocs

def extract_wazuh_iocs(alert):
    iocs = {"hashes": [], "ips": [], "domains": [], "urls": []}
    log = alert.get("full_log", "")
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", log)
    for h in hashes:
        if is_valid_hash(h):
            iocs["hashes"].append(h.lower())
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log)
    for ip in ips:
        if is_public_ip(ip):
            iocs["ips"].append(ip)
    urls = re.findall(r"https?://[^\s\"']+", log)
    for url in urls:
        iocs["urls"].append(url)
    return clean_iocs(iocs)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s\"']+")

SAFE_EXE_PREFIXES = (
    "/usr/", "/lib/", "/sbin/", "/bin/", "/snap/",
    "/var/ossec/bin/",
    "/usr/local/bin/velociraptor",
)

def _is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def _parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

def _is_suspicious_process(name, exe, cmdline, deleted):
    if deleted:
        return True
    if name in SECURITY_TOOLS:
        return False
    if name in ("bash", "sh") and not any(
        tool in cmdline.lower() for tool in HIGH_RISK_PROCESSES if tool not in ("bash", "sh")
    ):
        return False
    if name in HIGH_RISK_PROCESSES:
        return True
    if exe and not exe.startswith(SAFE_EXE_PREFIXES):
        return True
    return False

def extract_velociraptor_iocs(rows, source="velociraptor", alert_time=None, window_minutes=15):
    iocs = []
    seen = set()
    ref_time = _parse_time(alert_time)
    window = timedelta(minutes=window_minutes)

    def _add(ioc_type, value):
        key = (ioc_type, value)
        if key in seen:
            return
        seen.add(key)
        iocs.append({"type": ioc_type, "value": value, "source": source})

    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name", "")).lower()
        exe = str(row.get("Exe", ""))
        cmdline = str(row.get("CommandLine", ""))
        deleted = row.get("Deleted") is True

        if ref_time is not None and not deleted:
            proc_time = _parse_time(row.get("CreateTime"))
            if proc_time and abs(proc_time - ref_time) > window:
                continue

        if _is_suspicious_process(name, exe, cmdline, deleted):
            hashes = row.get("Hash") or row.get("Hashes") or {}
            if isinstance(hashes, dict):
                value = hashes.get("SHA256")
                if value:
                    value = value.lower().strip()
                    if len(value) == 64 and value not in USELESS_HASHES:
                        _add("hash", value)

        if cmdline:
            for ip in IP_REGEX.findall(cmdline):
                if _is_public_ip(ip):
                    _add("ip", ip)
            for url in URL_REGEX.findall(cmdline):
                _add("url", url)
                m = re.search(r"https?://([^/\s\"']+)", url)
                if m:
                    host = m.group(1).split(":")[0]
                    if not IP_REGEX.fullmatch(host):
                        _add("domain", host)

    return iocs

def extract_iocs(artifact, results):
    output = []
    velo_iocs = extract_velociraptor_iocs(results)
    for ioc in velo_iocs:
        output.append(ioc)
    return {"iocs": output}

def merge_iocs(wazuh, velociraptor):
    final = {"hashes": [], "ips": [], "domains": [], "urls": []}
    for key in final:
        final[key] = list(set(wazuh.get(key, []) + velociraptor.get(key, [])))
    return final

def ioc_statistics(iocs):
    return {
        "total": sum(len(x) for x in iocs.values()),
        "hashes": len(iocs["hashes"]),
        "ips": len(iocs["ips"]),
        "domains": len(iocs["domains"]),
        "urls": len(iocs["urls"])
    }

def flatten_ioc_dict(iocs, source=None):
    result = []
    if not iocs:
        return result
    for ioc_type, values in iocs.items():
        for value in values:
            item = {"type": ioc_type.rstrip("s"), "value": value}
            if source:
                item["source"] = source
            result.append(item)
    return result