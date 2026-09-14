import sqlite3
from datetime import datetime

DB_PATH="/app/incidents.db"

def build_fingerprint(normalized):
    normalized=normalized or {}

    rule_id=str(normalized.get("rule_id","")).strip()
    incident_type=str(normalized.get("incident_type","")).strip()
    hostname=str(normalized.get("hostname","")).strip()

    return f"{rule_id}|{incident_type}|{hostname}"

def get_known_label(normalized):
    fingerprint=build_fingerprint(normalized)

    conn=sqlite3.connect(DB_PATH)
    cursor=conn.cursor()

    cursor.execute(
        """
        SELECT label,occurrences
        FROM alert_labels
        WHERE fingerprint=?
        """,
        (fingerprint,)
    )

    row=cursor.fetchone()

    if row:
        label,occurrences=row

        cursor.execute(
            """
            UPDATE alert_labels
            SET occurrences=occurrences+1,
                last_seen=?
            WHERE fingerprint=?
            """,
            (
                datetime.utcnow().isoformat(),
                fingerprint
            )
        )

        conn.commit()
        conn.close()

        return {
            "known":True,
            "label":label,
            "fingerprint":fingerprint,
            "occurrences":occurrences+1
        }

    conn.close()

    return {
        "known":False,
        "label":None,
        "fingerprint":fingerprint,
        "occurrences":0
    }

def save_label(normalized,label):
    fingerprint=build_fingerprint(normalized)
    now=datetime.utcnow().isoformat()
    normalized=normalized or {}

    rule_id=str(normalized.get("rule_id",""))
    incident_type=str(normalized.get("incident_type",""))
    hostname=str(normalized.get("hostname",""))

    conn=sqlite3.connect(DB_PATH)
    cursor=conn.cursor()

    cursor.execute(
        """
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
            label=excluded.label,
            occurrences=alert_labels.occurrences+1,
            last_seen=excluded.last_seen
        """,
        (
            fingerprint,
            rule_id,
            incident_type,
            hostname,
            label,
            now,
            now
        )
    )

    conn.commit()
    conn.close()

    return {
        "success":True,
        "fingerprint":fingerprint,
        "label":label
    }

def build_alert_fingerprint(rule_id,incident_type,hostname):
    return (
        f"{rule_id}|"
        f"{incident_type or ''}|"
        f"{hostname or ''}"
    )

def build_behavior_fingerprint(rule_id,incident_type):
    return (
        f"{rule_id}|"
        f"{incident_type or ''}"
    )

def calculate_memory_statistics(rows):
    total=len(rows)

    if total==0:
        return {
            "total":0,
            "true_positive":0,
            "false_positive":0,
            "tp_rate":0.0
        }

    true_positive=sum(
        1
        for row in rows
        if str(row.get("label","")).upper()=="TRUE_POSITIVE"
    )

    false_positive=sum(
        1
        for row in rows
        if str(row.get("label","")).upper()=="FALSE_POSITIVE"
    )

    labeled=true_positive+false_positive

    tp_rate=(
        true_positive/labeled
        if labeled>0
        else 0.0
    )

    return {
        "total":total,
        "true_positive":true_positive,
        "false_positive":false_positive,
        "tp_rate":round(tp_rate,4)
    }