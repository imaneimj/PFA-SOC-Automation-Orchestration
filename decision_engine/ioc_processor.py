from ioc_rules import *
import ipaddress
def process_iocs(iocs):
    filtered = []
    seen = set()
    for ioc in iocs:
        value = str(ioc.get("value", "")).lower().strip()
        t = ioc.get("type")
        key = (t, value)
        if key in seen:
            continue
        seen.add(key)
        score = 0
        reason = ""
        if t == "hash":
            if value in USELESS_HASHES:
                continue
            score = 80
            reason = "Unknown hash"
        elif t == "ip":
            try:
                ip = ipaddress.ip_address(value)
                if not ip.is_global:
                    continue
            except:
                continue
            if value in KNOWN_IPS:
                continue
            score = 90
            reason = "External IP"
        elif t == "domain":
            if any(
                value == x or value.endswith("." + x)
                for x in SAFE_DOMAINS
            ):
                continue
            score = 90
            reason = "Unknown domain"
        elif t == "url":
            if any(x in value for x in SAFE_URL_KEYWORDS):
                continue
            score = 95
            reason = "Suspicious URL"
        else:
            continue
        ioc["value"] = value
        ioc["score"] = score
        ioc["reason"] = reason
        filtered.append(ioc)
    return filtered
TYPE_TO_PLURAL = {"hash": "hashes", "ip": "ips", "domain": "domains", "url": "urls",}
def split_iocs(iocs):
    result = {"hashes": [],"ips": [],"domains": [],"urls": [] }
    for i in iocs:
        key = TYPE_TO_PLURAL.get(i["type"])
        if key:
            result[key].append(i)
    return result
def ioc_statistics(iocs):
    return {
        "total": len(iocs),
        "hashes": len([x for x in iocs if x["type"] == "hash"]),
        "ips": len([x for x in iocs if x["type"] == "ip"]),
        "domains": len([x for x in iocs if x["type"] == "domain"]),
        "urls": len([x for x in iocs if x["type"] == "url"])
    }