import re

NOISE_PATH_PATTERNS=[
    r"/.*\.config/dconf/user$",
    r"/.*\.config/tiling-assistant/tiledSessionRestore.*\.json$",
    r"/.*\.cache(?:/|$)",
    r"/.*\.local/share/nautilus(?:/|$)",
    r"/.*\.local/share/gvfs-metadata(?:/|$)",
    r"/.*\.local/share/tracker3(?:/|$)",
    r"/.*\.local/share/recently-used\.xbel$",
    r"/.*\.mozilla/firefox/.*",
    r"/.*\.config/google-chrome/.*",
    r"/.*\.local/share/evolution(?:/|$)",
    r"/.*\.local/share/gnome-shell(?:/|$)",
    r"/.*\.local/share/gsettings(?:/|$)",
    r"^/tmp/\.X11-unix/.*",
    r"^/tmp/VQL_AllSockets_.*\.jsonl.*",
    r"goutputstream-[^/]+$",
    r"^/etc/cups/subscriptions\.conf(?:\.[0-9]+|[ON])$",
]

_compiled=[re.compile(pattern,re.IGNORECASE) for pattern in NOISE_PATH_PATTERNS]

def is_noise(path:str)->bool:
    if not path:
        return False
    path=str(path).strip()
    for pattern in _compiled:
        if pattern.search(path):
            print(f"[NOISE FILTER] MATCH pattern={pattern.pattern!r} path={path!r}")
            return True
    return False