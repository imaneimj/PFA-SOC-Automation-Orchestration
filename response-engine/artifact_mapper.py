ARTIFACTS={
    "Linux":{
        "AUTO":"Custom.Linux.Quarantine",
        "QUARANTINE":"Custom.Linux.Quarantine",
        "ISOLATE_NETWORK":"Custom.Linux.Quarantine",
        "BLOCK_IP":"Custom.Linux.BlockIP",
        "KILL_PROCESS":"Custom.Linux.KillProcess",
        "DELETE_FILE":"Custom.Linux.DeleteFile",
        "REMOVE_PERSISTENCE":"Custom.Linux.RemovePersistence",
        "ROLLBACK":"Custom.Linux.Rollback",
    },
    "Windows":{
        "AUTO":"Custom.Windows.Quarantine.Firewall",
        "QUARANTINE":"Custom.Windows.Quarantine.Firewall",
        "ISOLATE_NETWORK":"Custom.Windows.Quarantine.Firewall",
        "QUARANTINE_FIREWALL":"Custom.Windows.Quarantine.Firewall",
        "QUARANTINE_FULL":"Custom.Windows.Quarantine",
        "BLOCK_IP":"Custom.Windows.BlockIP",
        "KILL_PROCESS":"Custom.Windows.KillProcess",
        "DELETE_FILE":"Custom.Windows.DeleteFile",
        "REMOVE_PERSISTENCE":"Custom.Windows.RemovePersistence",
        "ROLLBACK":"Custom.Windows.Rollback",
        "ROLLBACK_FIREWALL":"Custom.Windows.Rollback.Firewall",
    },
    "MacOS":{
        "AUTO":"Custom.MacOS.Quarantine",
        "QUARANTINE":"Custom.MacOS.Quarantine",
        "ISOLATE_NETWORK":"Custom.MacOS.Quarantine",
        "BLOCK_IP":"Custom.MacOS.BlockIP",
        "KILL_PROCESS":"Custom.MacOS.KillProcess",
        "DELETE_FILE":"Custom.MacOS.DeleteFile",
        "REMOVE_PERSISTENCE":"Custom.MacOS.RemovePersistence",
        "ROLLBACK":"Custom.MacOS.Rollback",
    }
}

def get_artifact(platform,response):
    if platform not in ARTIFACTS:
        raise ValueError(f"Unsupported platform: {platform}")
    if response not in ARTIFACTS[platform]:
        raise ValueError(f"Unsupported response '{response}' for platform '{platform}'")
    return ARTIFACTS[platform][response]