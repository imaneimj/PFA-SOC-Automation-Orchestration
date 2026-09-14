import re
from analysis_rules import (
    INTERPRETERS,
    NETWORK_TOOLS,
    SYSTEM_PROCESSES,
    SECURITY_TOOLS,
    SUSPICIOUS_PATHS,
)
from planner import CAPABILITIES

IP_REGEX=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX=re.compile(r"https?://[^\s\"']+",re.IGNORECASE)
HASH_REGEX=re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
DOMAIN_REGEX=re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

SUSPICIOUS_COMMANDS={
    "powershell","pwsh","cmd.exe","wscript","cscript","mshta",
    "rundll32","regsvr32","certutil","bitsadmin","curl","wget",
    "nc","netcat","socat"
}

OBFUSCATION_KEYWORDS={
    "encodedcommand","frombase64string","base64","decode",
    "decode64","invoke-expression","iex ","downloadstring",
    "downloadfile"
}

PERSISTENCE_KEYWORDS={
    "run","runonce","startup","schtasks","scheduled task","cron",
    "crontab","systemd","service","authorized_keys","autorun",
    "registry","wmi"
}

FILE_ACTION_KEYWORDS={
    "create","created","write","written","modify","modified",
    "delete","deleted","rename","renamed","unlink"
}

PRIVILEGE_KEYWORDS={
    "sudo","setuid","setgid","uid=0","root","administrator",
    "admin","privilege"
}

def _safe_string(value):
    if value is None:
        return ""
    if isinstance(value,(dict,list,tuple,set)):
        return str(value)
    return str(value)

def _flatten_values(value):
    values=[]
    if isinstance(value,dict):
        for key,item in value.items():
            values.append(_safe_string(key))
            values.extend(_flatten_values(item))
    elif isinstance(value,(list,tuple,set)):
        for item in value:
            values.extend(_flatten_values(item))
    else:
        values.append(_safe_string(value))
    return values

def _row_text(row):
    return " ".join(_flatten_values(row)).lower()

def _contains_any(text,patterns):
    text=str(text).lower()
    return any(pattern.lower() in text for pattern in patterns)

def _extract_iocs(text):
    return {
        "ips":sorted(set(IP_REGEX.findall(text))),
        "urls":sorted(set(URL_REGEX.findall(text))),
        "hashes":sorted(set(HASH_REGEX.findall(text))),
        "domains":sorted(set(DOMAIN_REGEX.findall(text))),
    }

def _safe_bool(value):
    if isinstance(value,bool):
        return value
    if isinstance(value,str):
        return value.strip().lower() in {
            "true","1","yes","y","oui"
        }
    return bool(value)

def _unique(values):
    return list(dict.fromkeys(values))

def _count_rows(analysis,key):
    if not isinstance(analysis,dict):
        return 0
    value=analysis.get(key,[])
    return len(value) if isinstance(value,list) else 0

def _get_analysis(analyses,capability):
    value=analyses.get(capability,{})
    return value if isinstance(value,dict) else {}

def build_artifact_capability_index():
    index={}
    for capability,artifacts in CAPABILITIES.items():
        for artifact in artifacts:
            index.setdefault(artifact,set()).add(capability)
    return index

ARTIFACT_CAPABILITY_INDEX=build_artifact_capability_index()

def get_capabilities_for_artifact(artifact):
    return sorted(
        ARTIFACT_CAPABILITY_INDEX.get(
            str(artifact or ""),
            set()
        )
    )

def analyze_processes(results):
    processes=[r for r in results if isinstance(r,dict)]
    security=[]
    system=[]
    interpreters=[]
    network_tools=[]
    suspicious=[]

    for process in processes:
        name=str(process.get("Name","")).lower()
        exe=str(process.get("Exe","")).lower()
        cmdline=str(process.get("CommandLine","")).lower()

        if (
            name in SECURITY_TOOLS
            or any(t in exe for t in SECURITY_TOOLS)
        ):
            security.append(process.get("Name",name))
            continue

        if name in SYSTEM_PROCESSES:
            system.append(process.get("Name",name))

        if (
            name in INTERPRETERS
            or any(i in cmdline for i in INTERPRETERS)
        ):
            interpreters.append(cmdline or name)

        if (
            name in NETWORK_TOOLS
            or any(n in cmdline for n in NETWORK_TOOLS)
        ):
            network_tools.append(cmdline or name)

        if (
            any(p.lower() in exe for p in SUSPICIOUS_PATHS)
            or any(p.lower() in cmdline for p in SUSPICIOUS_PATHS)
        ):
            suspicious.append(cmdline or exe or name)

        if process.get("Deleted") is True:
            suspicious.append(f"{name} (deleted: {exe})")

    return {
        "category":"processes",
        "total":len(processes),
        "security":security,
        "system":system,
        "interpreters":interpreters,
        "network_tools":network_tools,
        "suspicious":suspicious,
        "data":processes,
    }

def analyze_network(results):
    connections=[r for r in results if isinstance(r,dict)]
    text=" ".join(_row_text(row) for row in connections)
    return {
        "category":"network",
        "count":len(connections),
        "iocs":_extract_iocs(text),
        "data":connections,
    }

def analyze_users(results):
    users=[r for r in results if isinstance(r,dict)]
    privileged=[]

    for user in users:
        text=_row_text(user)
        if _contains_any(text,PRIVILEGE_KEYWORDS):
            privileged.append(user)

    return {
        "category":"users",
        "count":len(users),
        "privileged":privileged,
        "data":users,
    }

def analyze_authentication(results):
    rows=[r for r in results if isinstance(r,dict)]
    failed=[]
    successful=[]
    privileged=[]

    for row in rows:
        text=_row_text(row)

        if "failed" in text or "failure" in text or "denied" in text:
            failed.append(row)

        if "success" in text or "successful" in text or "accepted" in text:
            successful.append(row)

        if _contains_any(text,PRIVILEGE_KEYWORDS):
            privileged.append(row)

    return {
        "category":"authentication",
        "total":len(rows),
        "failed":failed,
        "successful":successful,
        "privileged":privileged,
        "data":rows,
    }

def analyze_persistence(results):
    rows=[r for r in results if isinstance(r,dict)]
    suspicious=[]

    for row in rows:
        text=_row_text(row)
        if _contains_any(text,PERSISTENCE_KEYWORDS):
            suspicious.append(row)

    return {
        "category":"persistence",
        "total":len(rows),
        "suspicious":suspicious,
        "persistence_detected":bool(suspicious),
        "data":rows,
    }

def analyze_file_integrity(results):
    rows=[r for r in results if isinstance(r,dict)]
    created=[]
    modified=[]
    deleted=[]
    renamed=[]

    for row in rows:
        text=_row_text(row)

        if _contains_any(text,{"create","created"}):
            created.append(row)

        if _contains_any(
            text,
            {"modify","modified","write","written"}
        ):
            modified.append(row)

        if _contains_any(
            text,
            {"delete","deleted","unlink"}
        ):
            deleted.append(row)

        if _contains_any(
            text,
            {"rename","renamed"}
        ):
            renamed.append(row)

    return {
        "category":"file_integrity",
        "total":len(rows),
        "created":created,
        "modified":modified,
        "deleted":deleted,
        "renamed":renamed,
        "data":rows,
    }

def analyze_memory(results):
    rows=[r for r in results if isinstance(r,dict)]
    suspicious=[]

    for row in rows:
        text=_row_text(row)
        if (
            "injection" in text
            or "hollow" in text
            or "unmapped" in text
            or "rwx" in text
        ):
            suspicious.append(row)

    return {
        "category":"memory",
        "total":len(rows),
        "suspicious":suspicious,
        "data":rows,
    }

def analyze_system(results):
    rows=[r for r in results if isinstance(r,dict)]
    suspicious=[]

    for row in rows:
        text=_row_text(row)
        if _contains_any(text,PRIVILEGE_KEYWORDS):
            suspicious.append(row)

    return {
        "category":"system",
        "total":len(rows),
        "suspicious":suspicious,
        "data":rows,
    }

def analyze_powershell(results):
    rows=[r for r in results if isinstance(r,dict)]
    encoded=[]
    downloads=[]
    suspicious=[]

    for row in rows:
        text=_row_text(row)
        is_encoded=_contains_any(text,OBFUSCATION_KEYWORDS)
        is_download=(
            "download" in text
            or "invoke-webrequest" in text
            or "webclient" in text
        )

        if is_encoded:
            encoded.append(row)

        if is_download:
            downloads.append(row)

        if is_encoded or is_download:
            suspicious.append(row)

    return {
        "category":"powershell",
        "total":len(rows),
        "encoded":encoded,
        "downloads":downloads,
        "suspicious":suspicious,
        "data":rows,
    }

def analyze_malware(results):
    rows=[r for r in results if isinstance(r,dict)]
    suspicious=[]

    for row in rows:
        text=_row_text(row)
        if (
            "malware" in text
            or "yara" in text
            or "suspicious" in text
            or "trojan" in text
            or "ransomware" in text
        ):
            suspicious.append(row)

    return {
        "category":"malware",
        "total":len(rows),
        "suspicious":suspicious,
        "data":rows,
    }

def analyze_audit(results):
    rows=[r for r in results if isinstance(r,dict)]
    executions=[]
    files=[]
    network=[]
    privilege=[]

    for row in rows:
        text=_row_text(row)

        if _contains_any(
            text,
            {"execve","execute","execution","command","process"}
        ):
            executions.append(row)

        if _contains_any(text,FILE_ACTION_KEYWORDS):
            files.append(row)

        if (
            "connect" in text
            or "socket" in text
            or "network" in text
        ):
            network.append(row)

        if _contains_any(text,PRIVILEGE_KEYWORDS):
            privilege.append(row)

    return {
        "category":"audit",
        "total":len(rows),
        "executions":executions,
        "files":files,
        "network":network,
        "privilege":privilege,
        "data":rows,
    }

def analyze_generic_behavior(results):
    rows=[r for r in results if isinstance(r,dict)]
    text=" ".join(_row_text(row) for row in rows)
    iocs=_extract_iocs(text)
    indicators=[]

    if iocs["ips"]:
        indicators.append("ip_observed")
    if iocs["domains"]:
        indicators.append("domain_observed")
    if iocs["urls"]:
        indicators.append("url_observed")
    if iocs["hashes"]:
        indicators.append("hash_observed")
    if _contains_any(text,SUSPICIOUS_COMMANDS):
        indicators.append("suspicious_command")
    if _contains_any(text,OBFUSCATION_KEYWORDS):
        indicators.append("obfuscation")
    if _contains_any(text,PERSISTENCE_KEYWORDS):
        indicators.append("persistence")
    if _contains_any(text,FILE_ACTION_KEYWORDS):
        indicators.append("file_activity")
    if _contains_any(text,PRIVILEGE_KEYWORDS):
        indicators.append("privilege_activity")

    return {
        "category":"generic_behavior",
        "total":len(rows),
        "indicators":list(dict.fromkeys(indicators)),
        "iocs":iocs,
    }

def _build_process_zero_day_signals(analyses):
    process=_get_analysis(analyses,"PROCESS")
    suspicious=process.get("suspicious",[])
    interpreters=process.get("interpreters",[])
    network_tools=process.get("network_tools",[])
    memory=_get_analysis(analyses,"MEMORY")
    memory_suspicious=memory.get("suspicious",[])

    return {
        "suspicious_process":bool(suspicious),
        "living_off_the_land":bool(interpreters or network_tools),
        "process_injection":bool(memory_suspicious),
        "suspicious_count":len(suspicious),
        "interpreter_count":len(interpreters),
        "network_tool_count":len(network_tools),
        "memory_suspicious_count":len(memory_suspicious),
    }

def _build_network_zero_day_signals(analyses):
    network=_get_analysis(analyses,"NETWORK")
    iocs=network.get("iocs",{}) or {}
    ips=iocs.get("ips",[])
    domains=iocs.get("domains",[])
    urls=iocs.get("urls",[])
    audit=_get_analysis(analyses,"AUDIT")
    audit_network=audit.get("network",[])

    return {
        "ip_observed":bool(ips),
        "domain_observed":bool(domains),
        "url_observed":bool(urls),
        "network_activity_observed":bool(audit_network),
        "new_destination":bool(domains or ips),
        "ip_count":len(ips),
        "domain_count":len(domains),
        "url_count":len(urls),
        "network_event_count":len(audit_network),
    }

def _build_behavioral_zero_day_signals(analyses):
    generic=analyses.get("_generic",{})
    indicators=set(generic.get("indicators",[]))
    persistence=_get_analysis(analyses,"PERSISTENCE")
    powershell=_get_analysis(analyses,"POWERSHELL")
    memory=_get_analysis(analyses,"MEMORY")
    audit=_get_analysis(analyses,"AUDIT")
    process_analysis=_get_analysis(analyses,"PROCESS")

    rare_behavior=(
        "suspicious_command" in indicators
        or "obfuscation" in indicators
        or "persistence" in indicators
    )

    suspicious_command_chain=(
        "suspicious_command" in indicators
        and (
            bool(powershell.get("downloads",[]))
            or bool(powershell.get("encoded",[]))
        )
    )

    abnormal_execution=bool(audit.get("executions",[]))

    living_off_the_land=(
        "suspicious_command" in indicators
        and bool(process_analysis.get("interpreters",[]))
    )

    process_injection=bool(memory.get("suspicious",[]))

    return {
        "rare_behavior":rare_behavior,
        "unexpected_parent_child":False,
        "suspicious_command_chain":suspicious_command_chain,
        "abnormal_execution":abnormal_execution,
        "living_off_the_land":living_off_the_land,
        "process_injection":process_injection,
        "persistence_detected":persistence.get(
            "persistence_detected",
            False
        ),
    }

def _build_novelty_signals(analyses):
    generic=analyses.get("_generic",{})
    indicators=generic.get("indicators",[])
    novelty_indicators=[]

    if "ip_observed" in indicators:
        novelty_indicators.append("new_ioc_candidate")

    if "domain_observed" in indicators:
        novelty_indicators.append("new_destination_candidate")

    if "suspicious_command" in indicators:
        novelty_indicators.append("unknown_behavior_candidate")

    if "obfuscation" in indicators:
        novelty_indicators.append("obfuscated_behavior_candidate")

    return {
        "indicators":novelty_indicators
    }

def build_zero_day_evidence(analyses,generic_behavior):
    analyses=dict(analyses or {})
    analyses["_generic"]=generic_behavior or {}

    process=_build_process_zero_day_signals(analyses)
    network=_build_network_zero_day_signals(analyses)
    behavioral=_build_behavioral_zero_day_signals(analyses)
    novelty=_build_novelty_signals(analyses)

    generic_indicators=(
        generic_behavior.get("indicators",[])
        if isinstance(generic_behavior,dict)
        else []
    )

    iocs=(
        generic_behavior.get("iocs",{})
        if isinstance(generic_behavior,dict)
        else {}
    )

    new_ioc_candidate=bool(novelty.get("indicators"))
    unknown_ioc="unknown_behavior_candidate" in novelty.get(
        "indicators",[]
    )

    new_process_candidate=(
        process.get("suspicious_process",False)
        or process.get("living_off_the_land",False)
    )

    new_destination_candidate=network.get(
        "new_destination",
        False
    )

    indicators=[]

    if new_ioc_candidate:
        indicators.append("new_ioc_candidate")

    if new_process_candidate:
        indicators.append("new_process_candidate")

    if new_destination_candidate:
        indicators.append("new_destination_candidate")

    if unknown_ioc:
        indicators.append("unknown_behavior_candidate")

    if behavioral.get("rare_behavior"):
        indicators.append("rare_behavior")

    if behavioral.get("suspicious_command_chain"):
        indicators.append("suspicious_command_chain")

    if behavioral.get("living_off_the_land"):
        indicators.append("living_off_the_land")

    if behavioral.get("process_injection"):
        indicators.append("process_injection")

    indicators=_unique(indicators)

    return {
        "new_ioc_candidate":new_ioc_candidate,
        "new_process_candidate":new_process_candidate,
        "new_destination_candidate":new_destination_candidate,
        "unknown_ioc":unknown_ioc,
        "behavioral":{**behavioral},
        "network":{**network},
        "process":{**process},
        "novelty":{**novelty},
        "indicators":indicators,
        "iocs":iocs,
        "generic_indicators":generic_indicators,
        "source":"evidence_analyzer",
        "note":(
            "These are behavioral and novelty candidates "
            "(qualitative signals only, no score). They are "
            "not proof of a zero-day vulnerability."
        ),
    }

CAPABILITY_ANALYZERS={
    "PROCESS":analyze_processes,
    "NETWORK":analyze_network,
    "AUTHENTICATION":analyze_authentication,
    "PERSISTENCE":analyze_persistence,
    "FILE_INTEGRITY":analyze_file_integrity,
    "MEMORY":analyze_memory,
    "USER":analyze_users,
    "SYSTEM":analyze_system,
    "POWERSHELL":analyze_powershell,
    "MALWARE":analyze_malware,
    "AUDIT":analyze_audit,
}

def process_evidence(artifact,results):
    artifact=str(artifact or "")
    results=results or []
    capabilities=get_capabilities_for_artifact(artifact)
    analyses={}

    for capability in capabilities:
        analyzer=CAPABILITY_ANALYZERS.get(capability)
        if analyzer:
            try:
                analyses[capability]=analyzer(results)
            except Exception as exc:
                analyses[capability]={
                    "category":capability.lower(),
                    "error":str(exc),
                }

    generic_behavior=analyze_generic_behavior(results)
    zero_day_evidence=build_zero_day_evidence(
        analyses,
        generic_behavior
    )

    return {
        "artifact":artifact,
        "capabilities":capabilities,
        "analyses":analyses,
        "behavior":generic_behavior,
        "zero_day":zero_day_evidence,
        "data":results,
    }

def merge_zero_day_evidences(evidences):
    evidences=[
        e for e in (evidences or [])
        if isinstance(e,dict)
    ]

    if not evidences:
        return {}

    indicators=[]
    generic_indicators=[]
    iocs={
        "ips":[],
        "urls":[],
        "hashes":[],
        "domains":[],
    }

    process_suspicious=False
    process_living_off_land=False
    process_injection=False
    network_new_destination=False
    behavioral_rare=False
    behavioral_chain=False
    behavioral_lotl=False
    behavioral_injection=False
    behavioral_persistence=False

    for ev in evidences:
        indicators.extend(ev.get("indicators",[]))
        generic_indicators.extend(ev.get("generic_indicators",[]))

        ev_iocs=ev.get("iocs",{}) or {}

        for key in iocs:
            iocs[key].extend(ev_iocs.get(key,[]))

        process=ev.get("process",{}) or {}

        if process.get("suspicious_process"):
            process_suspicious=True

        if process.get("living_off_the_land"):
            process_living_off_land=True

        if process.get("process_injection"):
            process_injection=True

        network=ev.get("network",{}) or {}

        if network.get("new_destination"):
            network_new_destination=True

        behavioral=ev.get("behavioral",{}) or {}

        if behavioral.get("rare_behavior"):
            behavioral_rare=True

        if behavioral.get("suspicious_command_chain"):
            behavioral_chain=True

        if behavioral.get("living_off_the_land"):
            behavioral_lotl=True

        if behavioral.get("process_injection"):
            behavioral_injection=True

        if behavioral.get("persistence_detected"):
            behavioral_persistence=True

    for key in iocs:
        iocs[key]=sorted(set(iocs[key]))

    return {
        "indicators":list(dict.fromkeys(indicators)),
        "generic_indicators":list(dict.fromkeys(generic_indicators)),
        "iocs":iocs,
        "process":{
            "suspicious_process":process_suspicious,
            "living_off_the_land":process_living_off_land,
            "process_injection":process_injection,
        },
        "network":{
            "new_destination":network_new_destination,
        },
        "behavioral":{
            "rare_behavior":behavioral_rare,
            "suspicious_command_chain":behavioral_chain,
            "living_off_the_land":behavioral_lotl,
            "process_injection":behavioral_injection,
            "persistence":behavioral_persistence,
        },
        "source":"artifact_evidence_merge",
    }