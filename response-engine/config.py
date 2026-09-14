import os

HOST=os.getenv("HOST","0.0.0.0")
PORT=int(os.getenv("PORT",8095))

VELOCIRAPTOR={
    "config_file":os.getenv("VELOCIRAPTOR_CONFIG","api_client.yaml"),
    "poll_interval":int(os.getenv("VELOCIRAPTOR_POLL_INTERVAL",2)),
    "max_wait":int(os.getenv("VELOCIRAPTOR_MAX_WAIT",300))
}

VELOCIRAPTOR_FRONTEND={
    "ip":os.getenv("VELOCIRAPTOR_FRONTEND_IP","10.0.2.1"),
    "port":os.getenv("VELOCIRAPTOR_FRONTEND_PORT","8000")
}

NOTIFICATION={
    "enabled":True,
    "critical":True,
    "analyst":True,
    "monitor":True
}

AUTO_RESPONSE={
    "AUTO_CONTAIN":False,
    "AUTO_RESPONSE":True,
    "ANALYST_APPROVAL":True,
    "MONITOR":False,
    "FALSE_POSITIVE":False
}

SUPPORTED_PLATFORMS=[
    "Linux",
    "Windows",
    "MacOS"
]