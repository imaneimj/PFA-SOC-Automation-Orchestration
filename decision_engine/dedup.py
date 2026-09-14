import time
import threading
DEDUP_WINDOW_SECONDS = 100
_last_collect = {}
_lock = threading.Lock()
def should_collect(
    hostname: str,
    rule_id: str,
    process_name: str = "",
    command_line: str = "",
    parent_process: str = "",
    username: str = "",
    ioc: dict = None):
    if not hostname:
        return True
    if ioc is None:
        ioc = {}
    ips = tuple(sorted(ioc.get("ips", [])))
    urls = tuple(sorted(ioc.get("urls", [])))
    hashes = tuple(sorted(ioc.get("hashes", [])))
    domains = tuple(sorted(ioc.get("domains", [])))
    key = (hostname,rule_id,process_name,command_line,parent_process,username,
           ips,urls,hashes,domains)
    now = time.time()
    with _lock:
        last = _last_collect.get(key)
        if last and now - last < DEDUP_WINDOW_SECONDS:
            return False
        _last_collect[key] = now
    return True