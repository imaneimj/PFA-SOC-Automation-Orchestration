import time
from datetime import datetime

SUSPICIOUS_GROUPS={
    "authentication_failed","authentication_success","sshd",
    "powershell","process_monitor","sysmon_event1","sudo",
    "mimikatz","lsass","rootcheck","syscheck","fim",
    "suricata","audit_command"
}

SUSPICIOUS_DECODERS={"sshd","pam","auditd"}

SUSPICIOUS_DESCRIPTIONS=(
    "failed password","authentication failure","accepted password",
    "session opened","invalid user","powershell","encodedcommand",
    "mimikatz","lsass","port scan","nmap","clear logs",
    "disable security","scheduled task"
)

NOISY_FILE_PATTERNS=(
    "/.local/share/nautilus/",
    "/.config/dconf/",
    "/.cache/",
    "/.local/share/recently-used.xbel",
    "/.mozilla/firefox/",
    "/.config/google-chrome/",
    "/.local/share/gvfs-metadata/",
    "/.local/share/tracker3/",
    "/tmp/.X11-unix/",
    "/.local/share/evolution/",
    "/.local/share/gnome-shell/",
    "/.local/share/gsettings/",
    "/.local/state/",
    "/.config/tiling-assistant/"
)

NOISY_FILE_SUFFIXES=(".db-shm",".db-wal",".lock",".swp",".tmp")

def _is_noisy_file_event(alert):
    path=((alert.get("syscheck",{}) or {}).get("path") or alert.get("path") or "").lower()
    if not path:
        return False
    if any(pattern in path for pattern in NOISY_FILE_PATTERNS):
        print("[FILTER] Noisy FIM path:",path)
        return True
    if any(path.endswith(suffix) for suffix in NOISY_FILE_SUFFIXES):
        print("[FILTER] Noisy FIM suffix:",path)
        return True
    return False

STARTUP_RULE_IDS={"503","504","530","533"}
STARTUP_GRACE_PERIOD=180
_agent_boot_times={}
BURST_WINDOW=30
BURST_THRESHOLD=8
_agent_alert_history={}

def _parse_timestamp(alert):
    ts=alert.get("timestamp")
    if not ts:
        return time.time()
    try:
        return datetime.strptime(
            ts.split(".")[0],
            "%Y-%m-%dT%H:%M:%S"
        ).timestamp()
    except Exception:
        return time.time()

def _mark_boot_if_needed(alert,agent_id,now):
    rule_id=str(alert.get("rule_id",""))
    if rule_id in STARTUP_RULE_IDS:
        _agent_boot_times[agent_id]=now
        print(
            f"[BOOT] Démarrage détecté pour l'agent {agent_id} "
            f"(rule_id={rule_id})"
        )

def _is_in_boot_grace_period(agent_id,now):
    boot_time=_agent_boot_times.get(agent_id)
    if boot_time is None:
        return False
    return now-boot_time<=STARTUP_GRACE_PERIOD

def _is_boot_burst(alert,agent_id,now):
    groups=alert.get("groups",[])
    if "syscheck" not in groups:
        return False

    history=_agent_alert_history.setdefault(agent_id,[])
    history.append(now)
    cutoff=now-BURST_WINDOW
    _agent_alert_history[agent_id]=[
        t for t in history if t>=cutoff
    ]

    if len(_agent_alert_history[agent_id])>=BURST_THRESHOLD:
        print(
            f"[BOOT] Rafale syscheck détectée pour l'agent {agent_id} "
            f"({len(_agent_alert_history[agent_id])} alertes en "
            f"{BURST_WINDOW}s) -> traité comme redémarrage"
        )
        _agent_boot_times[agent_id]=now
        return True

    return False

def _is_startup_noise(alert):
    agent_id=alert.get("agent_id")
    rule_id=str(alert.get("rule_id",""))

    print(
        f"[DEBUG STARTUP] agent_id={agent_id!r} | "
        f"rule_id={rule_id!r} | "
        f"timestamp={alert.get('timestamp')!r}"
    )

    if not agent_id:
        print("[DEBUG STARTUP] Aucun agent_id -> pas de startup detection")
        return False

    now=_parse_timestamp(alert)

    print(
        f"[DEBUG STARTUP] now={now} | "
        f"boot_time={_agent_boot_times.get(agent_id)}"
    )

    _mark_boot_if_needed(alert,agent_id,now)

    if _is_in_boot_grace_period(agent_id,now):
        print(
            f"[BOOT] Alerte ignorée pendant la période de grâce "
            f"(agent={agent_id})"
        )
        return True

    if _is_boot_burst(alert,agent_id,now):
        return True

    return False

CRITICAL_MITRE_TECHNIQUES={
    "Data Encrypted for Impact",
    "Inhibit System Recovery",
    "Data Destruction",
    "Network Denial of Service",
    "Endpoint Denial of Service"
}

HIGH_RISK_MITRE_TECHNIQUES={
    "Command and Control",
    "Exfiltration Over C2 Channel",
    "Ingress Tool Transfer",
    "Valid Accounts",
    "Remote Services",
    "Scheduled Task/Job",
    "Boot or Logon Autostart Execution"
}

CRITICAL_MITRE_TACTICS={
    "Command and Control",
    "Exfiltration"
}

CRITICAL_GROUPS={
    "ransomware",
    "malware",
    "trojan",
    "mimikatz",
    "lsass",
    "suricata"
}

HIGH_RISK_GROUPS={
    "powershell",
    "process_monitor",
    "sysmon_event1",
    "audit_command"
}

def _is_critical_override(alert):
    mitre=alert.get("mitre",{}) or {}

    tactics={
        str(x).strip()
        for x in (mitre.get("tactic",[]) or [])
    }

    techniques={
        str(x).strip()
        for x in (mitre.get("technique",[]) or [])
    }

    groups={
        str(x).strip().lower()
        for x in (alert.get("groups",[]) or [])
    }

    rule_level=int(alert.get("rule_level",0) or 0)
    score=0
    reasons=[]

    critical_techniques=techniques&CRITICAL_MITRE_TECHNIQUES
    if critical_techniques:
        score+=6
        reasons.append(
            f"critical MITRE technique={critical_techniques}"
        )

    high_risk_techniques=techniques&HIGH_RISK_MITRE_TECHNIQUES
    if high_risk_techniques:
        score+=3
        reasons.append(
            f"high-risk MITRE technique={high_risk_techniques}"
        )

    high_risk_tactics=tactics&CRITICAL_MITRE_TACTICS
    if high_risk_tactics:
        score+=2
        reasons.append(
            f"high-risk MITRE tactic={high_risk_tactics}"
        )

    critical_groups=groups&CRITICAL_GROUPS
    if critical_groups:
        score+=5
        reasons.append(
            f"critical Wazuh groups={critical_groups}"
        )

    high_risk_groups=groups&HIGH_RISK_GROUPS
    if high_risk_groups:
        score+=2
        reasons.append(
            f"high-risk Wazuh groups={high_risk_groups}"
        )

    if rule_level>=12:
        score+=4
        reasons.append(
            f"very high Wazuh rule level={rule_level}"
        )
    elif rule_level>=10:
        score+=2
        reasons.append(
            f"high Wazuh rule level={rule_level}"
        )

    critical=score>=6

    if critical:
        print(
            f"[CRITICAL OVERRIDE] score={score} "
            f"tactics={tactics} techniques={techniques} "
            f"groups={groups} reasons={reasons}"
        )

    return critical

NOISY_DESCRIPTIONS=[
    "gnome-shell",
    "dconf",
    ".local/share",
    ".config/dconf"
]

def _is_noisy_description(alert):
    description=(
        alert.get("description")
        or alert.get("title")
        or alert.get("full_log")
        or ""
    ).lower()

    for item in NOISY_DESCRIPTIONS:
        if item in description:
            print("[FILTER] GNOME noisy event:",description)
            return True

    return False

def should_investigate(alert):
    if _is_critical_override(alert):
        return True

    if _is_noisy_file_event(alert):
        return False

    if _is_noisy_description(alert):
        return False

    if _is_startup_noise(alert):
        return False

    decoder=alert.get("decoder","")

    if decoder in SUSPICIOUS_DECODERS:
        return True

    if (
        alert["rule_level"]<5
        and not alert.get("mitre",{}).get("tactic")
        and not alert.get("mitre",{}).get("technique")
    ):
        return False

    mitre=alert.get("mitre",{})

    if mitre.get("tactic") or mitre.get("technique"):
        return True

    for group in alert.get("groups",[]):
        if group in SUSPICIOUS_GROUPS:
            return True

    description=(
        alert.get("description")
        or alert.get("title")
        or alert.get("full_log")
        or ""
    ).lower()

    if any(x in description for x in SUSPICIOUS_DESCRIPTIONS):
        return True

    return False