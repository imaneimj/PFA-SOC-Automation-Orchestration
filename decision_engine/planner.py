from taxonomy import INCIDENT_TYPES

CAPABILITIES = {
    "PROCESS": [
        "Windows.System.Pslist",
        "Linux.Sys.Pslist",
        "MacOS.Sys.Pslist",
    ],

    "AUDIT": [
        "Linux.Forensics.Auditd",
    ],

    "NETWORK": [
        "Windows.Network.NetstatEnriched",
        "Linux.Network.NetstatEnriched",
        "MacOS.Network.Netstat",
    ],

    "AUTHENTICATION": [
        "Windows.EventLogs.ExplicitLogon",
        "Windows.EventLogs.AlternateLogon",
        "Windows.EventLogs.RDPAuth",
        "Linux.Syslog.SSHLogin",
        "Linux.Sys.Users",
        "MacOS.System.Users",
    ],

    "PERSISTENCE": [
        "Windows.Sys.StartupItems",
        "Windows.System.Services",
        "Windows.System.TaskScheduler",
        "Windows.Persistence.PermanentWMIEvents",
        "Windows.Persistence.PowershellRegistry",
        "Windows.Persistence.PowershellProfile",
        "Windows.Sysinternals.Autoruns",
        "Linux.Sys.Crontab",
        "Linux.Sys.Services",
        "Linux.Ssh.AuthorizedKeys",
        "MacOS.System.Plist",
    ],

    "FILE_INTEGRITY": [
        "Windows.Search.FileFinder",
        "Windows.Forensics.Usn",
        "Linux.Search.FileFinder",
        "MacOS.Search.FileFinder",
    ],

    "MEMORY": [
        "Windows.Memory.Acquisition",
        "Windows.Memory.ProcessInfo",
    ],

    "USER": [
        "Windows.Sys.Users",
        "Linux.Sys.Users",
        "MacOS.System.Users",
    ],

    "SYSTEM": [
        "Windows.Sys.DiskInfo",
        "Windows.Sys.Interfaces",
        "Windows.System.HostsFile",
        "Linux.Network.InterfaceAddresses",
        "Linux.Mounts",
        "MacOS.System.Packages",
    ],

    "POWERSHELL": [
        "Custom.Artifact.SuspiciousPowerShell",
        "Windows.EventLogs.PowershellScriptblock",
        "Windows.System.PowerShell",
    ],

    "MALWARE": [
        "Windows.Detection.Yara.Process",
        "Windows.Detection.BinaryHunter",
        "Windows.Memory.ProcessInfo",
        "Windows.Network.NetstatEnriched",
        "Linux.Detection.Yara.Process",
        "Linux.Network.NetstatEnriched",
        "MacOS.Detection.Yara.Process",
        "MacOS.Network.Netstat",
    ],
}


PROFILES = {
    INCIDENT_TYPES["AUTHENTICATION"]: {
        "priority": "Medium",
        "capabilities": [
            "AUTHENTICATION",
            "NETWORK",
            "USER",
            "PROCESS",
        ],
    },

    INCIDENT_TYPES["EXECUTION"]: {
        "priority": "High",
        "capabilities": [
            "PROCESS",
            "AUDIT",
            "NETWORK",
            "POWERSHELL",
            "FILE_INTEGRITY",
            "SYSTEM",
        ],
    },

    INCIDENT_TYPES["PERSISTENCE"]: {
        "priority": "High",
        "capabilities": [
            "PROCESS",
            "PERSISTENCE",
            "FILE_INTEGRITY",
            "USER",
            "AUDIT",
        ],
    },

    INCIDENT_TYPES["PRIVILEGE_ESCALATION"]: {
        "priority": "High",
        "capabilities": [
            "PROCESS",
            "AUTHENTICATION",
            "USER",
            "PERSISTENCE",
            "AUDIT",
        ],
    },

    INCIDENT_TYPES["DEFENSE_EVASION"]: {
        "priority": "Critical",
        "capabilities": [
            "PROCESS",
            "PERSISTENCE",
            "FILE_INTEGRITY",
            "SYSTEM",
            "MEMORY",
        ],
    },

    INCIDENT_TYPES["CREDENTIAL_ACCESS"]: {
        "priority": "Critical",
        "capabilities": [
            "AUTHENTICATION",
            "USER",
            "PROCESS",
            "NETWORK",
            "PERSISTENCE",
            "MEMORY",
        ],
    },

    INCIDENT_TYPES["DISCOVERY"]: {
        "priority": "Medium",
        "capabilities": [
            "PROCESS",
            "NETWORK",
            "USER",
            "SYSTEM",
        ],
    },

    INCIDENT_TYPES["LATERAL_MOVEMENT"]: {
        "priority": "High",
        "capabilities": [
            "NETWORK",
            "PROCESS",
            "AUTHENTICATION",
        ],
    },

    INCIDENT_TYPES["BRUTE_FORCE"]: {
        "priority": "High",
        "capabilities": [
            "AUTHENTICATION",
            "NETWORK",
            "USER",
            "PROCESS",
        ],
    },

    INCIDENT_TYPES["COMMAND_AND_CONTROL"]: {
        "priority": "Critical",
        "capabilities": [
            "NETWORK",
            "PROCESS",
            "FILE_INTEGRITY",
        ],
    },

    INCIDENT_TYPES["EXFILTRATION"]: {
        "priority": "Critical",
        "capabilities": [
            "NETWORK",
            "PROCESS",
            "FILE_INTEGRITY",
        ],
    },

    INCIDENT_TYPES["IMPACT"]: {
        "priority": "Critical",
        "capabilities": [
            "PROCESS",
            "FILE_INTEGRITY",
            "MEMORY",
        ],
    },

    INCIDENT_TYPES["MALWARE"]: {
        "priority": "Critical",
        "capabilities": [
            "PROCESS",
            "NETWORK",
            "MEMORY",
            "FILE_INTEGRITY",
            "PERSISTENCE",
        ],
    },

    INCIDENT_TYPES["NETWORK_ATTACK"]: {
        "priority": "Medium",
        "capabilities": [
            "NETWORK",
            "PROCESS",
        ],
    },

    INCIDENT_TYPES["FILE_INTEGRITY"]: {
        "priority": "Medium",
        "capabilities": [
            "FILE_INTEGRITY",
            "PROCESS",
            "SYSTEM",
        ],
    },

    INCIDENT_TYPES["POLICY_VIOLATION"]: {
        "priority": "Low",
        "capabilities": [
            "USER",
            "SYSTEM",
        ],
    },

    INCIDENT_TYPES["SYSTEM"]: {
        "priority": "Low",
        "capabilities": [
            "PROCESS",
            "SYSTEM",
        ],
    },

    INCIDENT_TYPES["OTHER"]: {
        "priority": "Low",
        "capabilities": [],
    },
}


def filter_artifacts(artifacts, platform):
    if not platform:
        return []

    prefix = {
        "Windows": "Windows",
        "Linux": "Linux",
        "MacOS": "MacOS",
    }.get(platform)

    if not prefix:
        return []

    return [
        artifact
        for artifact in artifacts
        if artifact.startswith(prefix)
    ]


def add_ioc_artifacts(artifacts, ioc, platform):
    if not ioc:
        return artifacts

    if platform == "Windows":

        if (
            ioc.get("ips")
            or ioc.get("domains")
            or ioc.get("urls")
        ):
            artifacts.extend([
                "Windows.Network.NetstatEnriched",
                "Windows.System.Pslist",
            ])

        if ioc.get("hashes"):
            artifacts.extend([
                "Windows.Search.FileFinder",
                "Windows.Detection.BinaryHunter",
            ])

    elif platform == "Linux":

        if (
            ioc.get("ips")
            or ioc.get("domains")
            or ioc.get("urls")
        ):
            artifacts.extend([
                "Linux.Network.NetstatEnriched",
                "Linux.Sys.Pslist",
            ])

        if ioc.get("hashes"):
            artifacts.extend([
                "Linux.Search.FileFinder",
                "Linux.Detection.Yara.Glob",
            ])

    elif platform == "MacOS":

        if (
            ioc.get("ips")
            or ioc.get("domains")
            or ioc.get("urls")
        ):
            artifacts.extend([
                "MacOS.Network.Netstat",
                "MacOS.Sys.Pslist",
            ])

        if ioc.get("hashes"):
            artifacts.extend([
                "MacOS.Search.FileFinder",
                "MacOS.Detection.Yara.Glob",
            ])

    return list(dict.fromkeys(artifacts))


def build_plan(incident_type, platform, ioc):
    profile = PROFILES.get(
        incident_type,
        PROFILES[INCIDENT_TYPES["OTHER"]],
    )

    artifacts = []

    for capability in profile["capabilities"]:
        artifacts.extend(
            CAPABILITIES.get(capability, [])
        )

    if ioc:

        if ioc.get("ips"):
            artifacts.extend([
                "Windows.Network.NetstatEnriched",
                "Linux.Network.NetstatEnriched",
                "MacOS.Network.Netstat",
                "Windows.System.Pslist",
                "Linux.Sys.Pslist",
                "MacOS.Sys.Pslist",
            ])

        if ioc.get("hashes"):
            artifacts.extend([
                "Windows.Search.FileFinder",
                "Linux.Search.FileFinder",
                "MacOS.Search.FileFinder",
            ])

        if (
            ioc.get("domains")
            or ioc.get("urls")
        ):
            artifacts.extend([
                "Windows.Network.NetstatEnriched",
                "Linux.Network.NetstatEnriched",
                "MacOS.Network.Netstat",
            ])

        if ioc.get("urls"):
            artifacts.extend([
                "Windows.Network.Netstat",
                "Linux.Network.Netstat",
                "MacOS.Network.Netstat",
            ])

    artifacts = list(
        dict.fromkeys(artifacts)
    )

    artifacts = filter_artifacts(
        artifacts,
        platform,
    )

    artifacts = add_ioc_artifacts(
        artifacts,
        ioc,
        platform,
    )

    investigations = [
        {
            "tool": "velociraptor",
            "artifact": artifact,
        }
        for artifact in artifacts
    ]

    return {
        "priority": profile["priority"],
        "investigations": investigations,
    }