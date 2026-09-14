from datetime import datetime
def safe_get(data, keys, default=None):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current
def clamp(value, minimum=0, maximum=100):
    return max(minimum, min(value, maximum))
def current_timestamp():
    return datetime.utcnow().isoformat()
def count_if(items, key, expected):
    return sum(
        1
        for item in items
        if item.get(key) == expected
    )
def percentage(value, total):
    if total == 0:
        return 0
    return round((value / total) * 100, 2)