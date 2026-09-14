import uuid
import time
import threading

_LOCK = threading.Lock()
_STORE = {}
TTL_SECONDS = 3600

def create_pending(action: dict) -> str:
    token = uuid.uuid4().hex
    with _LOCK:
        _STORE[token] = {
            "action": action,
            "created_at": time.time(),
            "consumed": False
        }
    return token

def get_pending(token: str):
    with _LOCK:
        entry = _STORE.get(token)
    if entry is None:
        return None
    if entry["consumed"]:
        return None
    if time.time() - entry["created_at"] > TTL_SECONDS:
        return None
    return entry["action"]

def consume_pending(token: str):
    with _LOCK:
        entry = _STORE.get(token)
        if entry:
            entry["consumed"] = True