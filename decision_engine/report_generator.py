from datetime import datetime
import os
import json

from evidence_analyzer import analyze_processes

def _safe(value, default="Unknown"):
    if value is None or value == "":
        return default
    return value

def _sample_keys(rows, max_rows=20):
    keys = set()
    if not isinstance(rows, list):
        return keys
    for row in rows[:max_rows]:
        if isinstance(row, dict):
            keys.update(row.keys())
    return keys

def _classify_evidence_type(keys):
    file_markers = {"OSPath","Path","FullPath","Filename","FileName","Size","MTime","Ctime","SHA256","SHA1","MD5"}
    if keys & file_markers:
        return "file"
    process_markers = {"Pid","PID","PPid","PPID","Process","ProcessName","Name","CommandLine","Exe","Executable"}
    if len(keys & process_markers) >= 2:
        return "process"
    network_markers = {"RemoteAddr","LocalAddr","Raddr","Laddr","RemoteAddress","LocalAddress","RemoteIP","LocalIP","RemotePort","LocalPort","Rport","Lport","Family","Status","State","Proto","Protocol"}
    if keys & network_markers:
        return "network"
    auth_markers = {"TargetUserName","LogonType","IpAddress","AuthenticationPackageName","User","Username","SourceIP","SourceIp","Failure","Success"}
    if len(keys & auth_markers) >= 2:
        return "authentication"
    event_markers = {"EventID","EventId","Message","EventTime","Timestamp","Time","Type","RecordID","RecordId"}
    if keys & event_markers:
        return "event_log"
    persistence_markers = {"Command","Schedule","KeyPath","ValueName","Entry","PLIST","Label","Service","Unit","Cron"}
    if keys & persistence_markers:
        return "persistence"
    if {"User","Uid"} <= keys or {"Username","Uid"} <= keys or {"Name","Uid"} <= keys:
        return "users"
    return "generic"

def _get_any(row, *names):
    if not isinstance(row, dict):
        return None
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None

def _markdown(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return str(value)

class EvidenceReportGenerator:
    def __init__(self):
        self.lines = []

    def add_title(self):
        self.lines.append("# Incident Investigation Report\n")
        self.lines.append(f"**Generated :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.lines.append("")

    def add_alert(self, alert):
        self.lines.append("## 1. Alert Summary\n")
        hostname = alert.get("hostname") or alert.get("agent_name") or "Unknown"
        self.lines.append(f"**Host :** {hostname}")
        self.lines.append(f"**Platform :** {_safe(alert.get('platform'))} ({_safe(alert.get('agent_os'))} {_safe(alert.get('agent_os_version'), '')})")
        self.lines.append(f"**Architecture :** {_safe(alert.get('agent_architecture'))}")
        self.lines.append(f"**Agent ID :** {_safe(alert.get('agent_id'))}")
        self.lines.append(f"**Rule :** {_safe(alert.get('description') or alert.get('rule_description'))}")
        self.lines.append(f"**Rule ID :** {_safe(alert.get('rule_id'))}")
        self.lines.append(f"**Rule level :** {_safe(alert.get('rule_level'))} (fired {_safe(alert.get('rule_firedtimes'), 1)}x)")
        self.lines.append(f"**Timestamp :** {_safe(alert.get('timestamp'))}")
        if alert.get("location"):
            self.lines.append(f"**Location :** {alert.get('location')}")
        if alert.get("decoder"):
            self.lines.append(f"**Decoder :** {_markdown(alert.get('decoder'))}")
        if alert.get("groups"):
            self.lines.append(f"**Groups :** {_markdown(alert.get('groups'))}")
        mitre = alert.get("mitre") or {}
        tactics = mitre.get("tactic") or []
        techniques = mitre.get("technique") or []
        ids = mitre.get("id") or []
        if tactics or techniques or ids:
            self.lines.append(f"**MITRE Technique :** {', '.join(map(str, ids)) or '-'}")
            self.lines.append(f"**MITRE Tactic :** {', '.join(map(str, tactics)) or '-'}")
            self.lines.append(f"**MITRE Technique Name :** {', '.join(map(str, techniques)) or '-'}")
        self.lines.append("")

    def add_classification(self, classification):
        classification = classification or {}
        self.lines.append("## 2. Classification\n")
        self.lines.append(f"**Incident Type :** {_safe(classification.get('type') or classification.get('incident_type'))}")
        self.lines.append(f"**Confidence :** {_safe(classification.get('confidence'))}")
        self.lines.append(f"**Severity :** {_safe(classification.get('severity'))}")
        self.lines.append(f"**Classification source :** {_safe(classification.get('source'))}")
        self.lines.append(f"**Priority :** {_safe(classification.get('priority'))}")
        if classification.get("reason"):
            self.lines.append(f"**Reason :** {classification.get('reason')}")
        self.lines.append("")

    def add_host_info(self, alert):
        self.lines.append("## 3. Host Information\n")
        agent = alert.get("agent_info") or {}
        self.lines.append(f"**Hostname :** {_safe(alert.get('hostname'))}")
        self.lines.append(f"**Agent ID :** {_safe(alert.get('agent_id'))}")
        self.lines.append(f"**Platform :** {_safe(alert.get('platform'))}")
        os_info = agent.get("os") or {}
        if os_info:
            self.lines.append(f"**OS :** {_safe(os_info.get('name'))}")
            self.lines.append(f"**OS Version :** {_safe(os_info.get('version'))}")
            self.lines.append(f"**Architecture :** {_safe(os_info.get('arch'))}")
        if agent.get("ip"):
            self.lines.append(f"**Agent IP :** {agent.get('ip')}")
        self.lines.append("")

    def add_plan(self, artifacts):
        self.lines.append("## 4. Investigation Plan\n")
        if not artifacts:
            self.lines.append("No Velociraptor artifact was scheduled.")
            self.lines.append("")
            return
        for artifact in artifacts:
            self.lines.append(f"- {artifact}")
        self.lines.append("")

    def add_collection_summary(self, collections):
        self.lines.append("## 5. Collection Summary\n")
        if not collections:
            self.lines.append("No collection was performed.")
            self.lines.append("")
            return
        self.lines.append("| Artifact | Status | Flow ID | Records |")
        self.lines.append("|---|---|---|---:|")
        for collection in collections:
            artifact = collection.get("artifact", "Unknown")
            rows = collection.get("rows", 0)
            flow_id = collection.get("flow_id") or "-"
            status = "SUCCESS" if rows > 0 else "EMPTY"
            self.lines.append(f"| {artifact} | {status} | {flow_id} | {rows} |")
        self.lines.append("")

    def add_evidence(self, evidence):
        self.lines.append("## 6. Evidence Summary\n")
        if not evidence:
            self.lines.append("No evidence collected.")
            self.lines.append("")
            return
        for artifact, rows in evidence.items():
            self.lines.append(f"### {artifact}\n")
            if rows is None:
                self.lines.append("Artifact collection failed or returned no data.")
                self.lines.append("")
                continue
            if not isinstance(rows, list):
                rows = [rows]
            self.lines.append("**Collection status :** SUCCESS")
            self.lines.append(f"**Collected records :** {len(rows)}")
            if not rows:
                self.lines.append("\nNo result returned.\n")
                continue
            keys = _sample_keys(rows)
            evidence_type = _classify_evidence_type(keys)
            self.lines.append(f"**Evidence type :** {evidence_type}")
            self.lines.append("")
            dispatch = {
                "file": self._render_file,
                "process": self._render_process,
                "network": self._render_network,
                "authentication": self._render_authentication,
                "event_log": self._render_event_log,
                "persistence": self._render_persistence,
                "users": self._render_users,
                "generic": self._render_generic,
            }
            renderer = dispatch.get(evidence_type, self._render_generic)
            renderer(rows, keys)
            self.lines.append("")

    def _render_file(self, rows, keys):
        self.lines.append("#### File System Evidence\n")
        self.lines.append("| Path | Size | Owner | Permissions | SHA256 | MTime |")
        self.lines.append("|---|---:|---|---|---|---|")
        for row in rows[:100]:
            path = _get_any(row, "OSPath", "Path", "FullPath", "Filename", "FileName")
            size = _get_any(row, "Size")
            owner = _get_any(row, "Owner", "User", "Username")
            permissions = _get_any(row, "Mode", "Permissions", "FileMode")
            sha256 = _get_any(row, "SHA256", "Sha256", "sha256")
            mtime = _get_any(row, "MTime", "mtime", "Modified")
            self.lines.append(f"| `{path or '-'}` | {size or '-'} | {owner or '-'} | {permissions or '-'} | `{sha256 or '-'}` | {mtime or '-'} |")
        self.lines.append("")
        self.lines.append("**Assessment :** File system evidence successfully collected. Hashes and metadata should be correlated with IOC enrichment.")

    def _render_process(self, rows, keys):
        self.lines.append("#### Process Evidence\n")
        analysis = analyze_processes(rows)
        users = {_get_any(row, "Username", "User") for row in rows if _get_any(row, "Username", "User")}
        self.lines.append(f"- **Total running processes :** {len(rows)}")
        self.lines.append(f"- **Different users :** {len(users)}")
        self.lines.append("")
        self.lines.append("| PID | PPID | User | Process | Executable | Command Line |")
        self.lines.append("|---:|---:|---|---|---|---|")
        for row in rows[:100]:
            pid = _get_any(row, "Pid", "PID")
            ppid = _get_any(row, "PPid", "PPID")
            user = _get_any(row, "Username", "User")
            name = _get_any(row, "Name", "Process", "ProcessName")
            executable = _get_any(row, "Exe", "Executable", "ExePath")
            command = _get_any(row, "CommandLine", "Command", "Cmdline")
            self.lines.append(f"| {pid or '-'} | {ppid or '-'} | {user or '-'} | `{name or '-'}` | `{executable or '-'}` | `{command or '-'}` |")
        self.lines.append("")
        if analysis.get("security"):
            self.lines.append("**Security agents detected:**")
            for item in sorted(set(analysis["security"])):
                self.lines.append(f"- {item}")
            self.lines.append("")
        if analysis.get("interpreters"):
            self.lines.append("**Interpreters detected:**")
            for item in sorted(set(analysis["interpreters"])):
                self.lines.append(f"- {item}")
            self.lines.append("")
        if analysis.get("network_tools"):
            self.lines.append("**Network tools detected:**")
            for item in sorted(set(analysis["network_tools"])):
                self.lines.append(f"- {item}")
            self.lines.append("")
        if analysis.get("suspicious"):
            self.lines.append("### Potentially Suspicious Processes\n")
            for item in sorted(set(analysis["suspicious"])):
                self.lines.append(f"- ⚠ `{item}`")
        else:
            self.lines.append("No suspicious process execution detected.")
        self.lines.append("")
        self.lines.append("**Assessment :** Process inventory successfully collected.")

    def _render_network(self, rows, keys):
        self.lines.append("#### Network Connections\n")
        remote_ips = set()
        self.lines.append("| Local Address | Local Port | Remote Address | Remote Port | Protocol | State | PID | Process |")
        self.lines.append("|---|---:|---|---:|---|---|---:|---|")
        for row in rows[:200]:
            local = _get_any(row, "LocalAddr", "Laddr", "LocalAddress", "LocalIP")
            local_port = _get_any(row, "LocalPort", "Lport")
            remote = _get_any(row, "RemoteAddr", "Raddr", "RemoteAddress", "RemoteIP")
            remote_port = _get_any(row, "RemotePort", "Rport")
            protocol = _get_any(row, "Proto", "Protocol", "Family")
            state = _get_any(row, "State", "Status")
            pid = _get_any(row, "Pid", "PID")
            process = _get_any(row, "Process", "Name", "ProcessName")
            if remote:
                remote_ips.add(str(remote))
            self.lines.append(f"| `{local or '-'}` | {local_port or '-'} | `{remote or '-'}` | {remote_port or '-'} | {protocol or '-'} | {state or '-'} | {pid or '-'} | `{process or '-'}` |")
        self.lines.append("")
        self.lines.append(f"- **Connections collected :** {len(rows)}")
        self.lines.append(f"- **Unique remote IPs :** {len(remote_ips)}")
        if remote_ips:
            self.lines.append("- **Remote IPs observed:**")
            for ip in sorted(remote_ips):
                self.lines.append(f"  - `{ip}`")
        self.lines.append("")
        self.lines.append("**Assessment :** Network activity successfully collected. Remote IPs should be correlated with Wazuh, MISP and Cortex.")

    def _render_authentication(self, rows, keys):
        self.lines.append("#### Authentication Evidence\n")
        users = set()
        ips = set()
        self.lines.append("| Time | User | Source IP | Logon Type | Result |")
        self.lines.append("|---|---|---|---|---|")
        for row in rows[:200]:
            timestamp = _get_any(row, "Timestamp", "Time", "EventTime")
            user = _get_any(row, "TargetUserName", "Username", "User")
            ip = _get_any(row, "IpAddress", "SourceIP", "SourceIp")
            logon = _get_any(row, "LogonType")
            result = _get_any(row, "Status", "Success", "Failure")
            if user:
                users.add(str(user))
            if ip:
                ips.add(str(ip))
            self.lines.append(f"| {timestamp or '-'} | `{user or '-'}` | `{ip or '-'}` | {logon or '-'} | {result or '-'} |")
        self.lines.append("")
        self.lines.append(f"- **Authentication events :** {len(rows)}")
        self.lines.append(f"- **Distinct users :** {len(users)}")
        self.lines.append(f"- **Distinct source IPs :** {len(ips)}")
        self.lines.append("")
        self.lines.append("**Assessment :** Authentication evidence successfully collected.")

    def _render_event_log(self, rows, keys):
        self.lines.append("#### Event / Audit Evidence\n")
        self.lines.append("| Time | Event ID | Type | PID | User | Command | Message |")
        self.lines.append("|---|---|---|---:|---|---|---|")
        for row in rows[:200]:
            timestamp = _get_any(row, "Timestamp", "Time", "EventTime")
            event_id = _get_any(row, "EventID", "EventId")
            event_type = _get_any(row, "Type")
            pid = _get_any(row, "Pid", "PID")
            user = _get_any(row, "User", "Username")
            command = _get_any(row, "Command", "CommandLine")
            message = _get_any(row, "Message")
            self.lines.append(f"| {timestamp or '-'} | {event_id or '-'} | {event_type or '-'} | {pid or '-'} | `{user or '-'}` | `{command or '-'}` | {message or '-'} |")
        self.lines.append("")
        self.lines.append(f"**Events collected :** {len(rows)}")

    def _render_persistence(self, rows, keys):
        self.lines.append("#### Persistence Evidence\n")
        self.lines.append("| Entry | Command | Schedule | Service | Path |")
        self.lines.append("|---|---|---|---|---|")
        for row in rows[:100]:
            entry = _get_any(row, "Entry", "Label", "ValueName", "Name")
            command = _get_any(row, "Command")
            schedule = _get_any(row, "Schedule", "Cron")
            service = _get_any(row, "Service", "Unit")
            path = _get_any(row, "Path", "OSPath")
            self.lines.append(f"| `{entry or '-'}` | `{command or '-'}` | {schedule or '-'} | {service or '-'} | `{path or '-'}` |")
        self.lines.append("")
        self.lines.append("**Assessment :** Persistence artifacts collected. Entries should be reviewed for unauthorized persistence.")

    def _render_users(self, rows, keys):
        self.lines.append("#### User Accounts\n")
        self.lines.append("| Username | UID | GID | Home | Shell |")
        self.lines.append("|---|---:|---:|---|---|")
        for row in rows[:100]:
            username = _get_any(row, "Username", "User", "Name")
            uid = _get_any(row, "Uid", "UID")
            gid = _get_any(row, "Gid", "GID")
            home = _get_any(row, "Home", "HomeDir")
            shell = _get_any(row, "Shell")
            self.lines.append(f"| `{username or '-'}` | {uid or '-'} | {gid or '-'} | `{home or '-'}` | `{shell or '-'}` |")
        self.lines.append("")
        privileged = []
        for row in rows:
            uid = _get_any(row, "Uid", "UID")
            if str(uid) == "0":
                privileged.append(_get_any(row, "Username", "User", "Name"))
        self.lines.append(f"**Privileged UID 0 accounts :** {len(privileged)}")
        for user in privileged:
            self.lines.append(f"- ⚠ `{user}`")

    def _render_generic(self, rows, keys):
        self.lines.append("#### Raw Artifact Results\n")
        self.lines.append(f"**Returned fields :** {', '.join(sorted(map(str, keys))) or 'none'}")
        self.lines.append("")
        self.lines.append("```json")
        try:
            self.lines.append(json.dumps(rows[:50], ensure_ascii=False, indent=2, default=str))
        except Exception:
            self.lines.append(str(rows[:50]))
        self.lines.append("```")

    def add_ioc(self, ioc):
        self.lines.append("## 7. IOC Summary\n")
        if not ioc or not any(ioc.values()):
            self.lines.append("No IOC extracted.")
            self.lines.append("")
            return
        for key, values in ioc.items():
            if not values:
                continue
            self.lines.append(f"### {key.upper()}\n")
            if isinstance(values, list):
                self.lines.append("| IOC | Source | Score | Reason |")
                self.lines.append("|---|---|---:|---|")
                for item in values:
                    if isinstance(item, dict):
                        value = item.get("value", "-")
                        source = item.get("source", "-")
                        score = item.get("score", "-")
                        reason = item.get("reason", "-")
                    else:
                        value = str(item)
                        source = "-"
                        score = "-"
                        reason = "-"
                    self.lines.append(f"| `{value}` | {source} | {score} | {reason} |")
            else:
                self.lines.append(_markdown(values))
            self.lines.append("")

    def add_ioc_statistics(self, statistics):
        self.lines.append("## 8. IOC Statistics\n")
        statistics = statistics or {}
        self.lines.append(f"- **Total IOC :** {statistics.get('total', 0)}")
        self.lines.append(f"- **Hashes :** {statistics.get('hashes', 0)}")
        self.lines.append(f"- **IPs :** {statistics.get('ips', 0)}")
        self.lines.append(f"- **Domains :** {statistics.get('domains', 0)}")
        self.lines.append(f"- **URLs :** {statistics.get('urls', 0)}")
        self.lines.append("")

    def add_misp_enrichment(self, misp):
        self.lines.append("## 9. MISP Enrichment\n")
        if not misp:
            self.lines.append("No MISP enrichment available.")
            self.lines.append("")
            return
        self.lines.append("```json")
        self.lines.append(json.dumps(misp, ensure_ascii=False, indent=2, default=str))
        self.lines.append("```")
        self.lines.append("")

    def add_cortex_enrichment(self, cortex):
        self.lines.append("## 10. Cortex Enrichment\n")
        if not cortex:
            self.lines.append("No Cortex enrichment available.")
            self.lines.append("")
            return
        self.lines.append("```json")
        self.lines.append(json.dumps(cortex, ensure_ascii=False, indent=2, default=str))
        self.lines.append("```")
        self.lines.append("")

    def add_correlation(self, alert):
        self.lines.append("## 11. Evidence Correlation\n")
        iocs = alert.get("iocs") or []
        collections = alert.get("collections") or []
        self.lines.append(f"- **IOC indicators available :** {len(iocs)}")
        self.lines.append(f"- **Velociraptor collections :** {len(collections)}")
        incident_type = alert.get("incident_type", "Unknown")
        self.lines.append(f"- **Incident type :** {incident_type}")
        self.lines.append("")
        self.lines.append("Evidence should be correlated across Wazuh, Velociraptor, MISP and Cortex.")
        self.lines.append("")

    def add_timeline(self, alert, collections):
        self.lines.append("## 12. Investigation Timeline\n")
        timestamp = alert.get("timestamp")
        self.lines.append("| Time | Source | Event |")
        self.lines.append("|---|---|---|")
        self.lines.append(f"| {timestamp or '-'} | Wazuh | Alert detected |")
        for collection in collections or []:
            artifact = collection.get("artifact", "Unknown")
            flow_id = collection.get("flow_id")
            rows = collection.get("rows", 0)
            self.lines.append(f"| - | Velociraptor | {artifact} collected ({rows} records, flow={flow_id or '-'}) |")
        self.lines.append("")

    def add_raw_evidence(self, evidence):
        self.lines.append("## 13. Raw Evidence Appendix\n")
        if not evidence:
            self.lines.append("No raw evidence available.")
            self.lines.append("")
            return
        for artifact, rows in evidence.items():
            self.lines.append(f"### {artifact}\n")
            self.lines.append("```json")
            try:
                self.lines.append(json.dumps(rows[:100] if isinstance(rows, list) else rows, ensure_ascii=False, indent=2, default=str))
            except Exception:
                self.lines.append(str(rows))
            self.lines.append("```")
            self.lines.append("")

    def add_assessment(self, alert=None):
        self.lines.append("## 14. Preliminary Assessment\n")
        if alert:
            incident_type = alert.get("incident_type", "Unknown")
            severity = (alert.get("classification") or {}).get("severity", "Unknown")
            self.lines.append(f"**Incident type :** {incident_type}")
            self.lines.append(f"**Severity :** {severity}")
        self.lines.append("")
        self.lines.append("Evidence collection completed successfully.")
        self.lines.append("")

    def save(self, filename):
        os.makedirs("reports", exist_ok=True)
        path = os.path.join("reports", filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines))
        return path