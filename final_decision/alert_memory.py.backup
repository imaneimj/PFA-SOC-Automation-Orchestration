import sqlite3
from datetime import datetime

DB_PATH = "/app/incidents.db"


def build_fingerprint(normalized):
    rule_id = str(normalized.get("rule_id", "")).strip()
    incident_type = str(normalized.get("incident_type", "")).strip()
    hostname = str(normalized.get("hostname", "")).strip()

    return f"{rule_id}|{incident_type}|{hostname}"


def get_known_label(normalized):
    fingerprint = build_fingerprint(normalized)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT label, occurrences
        FROM alert_labels
        WHERE fingerprint = ?
    """, (fingerprint,))

    row = cursor.fetchone()

    if row:
        label, occurrences = row

        cursor.execute("""
            UPDATE alert_labels
            SET occurrences = occurrences + 1,
                last_seen = ?
            WHERE fingerprint = ?
        """, (
            datetime.utcnow().isoformat(),
            fingerprint
        ))

        conn.commit()

        conn.close()

        return {
            "known": True,
            "label": label,
            "fingerprint": fingerprint,
            "occurrences": occurrences + 1
        }

    conn.close()

    return {
        "known": False,
        "label": None,
        "fingerprint": fingerprint,
        "occurrences": 0
    }


def save_label(normalized, label):
    fingerprint = build_fingerprint(normalized)
    now = datetime.utcnow().isoformat()

    rule_id = str(normalized.get("rule_id", ""))
    incident_type = str(normalized.get("incident_type", ""))
    hostname = str(normalized.get("hostname", ""))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alert_labels (
            fingerprint,
            rule_id,
            incident_type,
            hostname,
            label,
            occurrences,
            first_seen,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(fingerprint)
        DO UPDATE SET
            label = excluded.label,
            occurrences = alert_labels.occurrences + 1,
            last_seen = excluded.last_seen
    """, (
        fingerprint,
        rule_id,
        incident_type,
        hostname,
        label,
        now,
        now
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "fingerprint": fingerprint,
        "label": label
    }