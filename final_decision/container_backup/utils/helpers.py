# utils/helpers.py

from datetime import datetime


def safe_get(data, keys, default=None):
    """
    Récupère une valeur dans un dictionnaire imbriqué.

    Exemple :
    safe_get(alert, ["classification", "severity"])
    """
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


def clamp(value, minimum=0, maximum=100):
    """
    Limite une valeur entre minimum et maximum.
    """

    return max(minimum, min(value, maximum))


def current_timestamp():
    """
    Retourne la date/heure actuelle au format ISO.
    """

    return datetime.utcnow().isoformat()


def count_if(items, key, expected):
    """
    Compte le nombre d'éléments ayant une valeur donnée.

    Exemple :
    count_if(cortex_results, "level", "malicious")
    """

    return sum(
        1
        for item in items
        if item.get(key) == expected
    )


def percentage(value, total):
    """
    Calcule un pourcentage.
    """

    if total == 0:
        return 0

    return round((value / total) * 100, 2)