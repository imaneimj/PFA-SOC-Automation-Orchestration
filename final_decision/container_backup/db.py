import sqlite3
import json
import threading
from datetime import datetime

DB_PATH = "/app/incidents.db"

_lock = threading.Lock()

CRITICAL_DECISIONS = {
    "AUTO_CONTAIN",
    "AUTO_RESPONSE",
    "ANALYST_APPROVAL"
}

DUPLICATE_WINDOW_SECONDS = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    timestamp TEXT,
    created_at TEXT,
    hostname TEXT,
    agent_id TEXT,
    platform TEXT,
    incident_type TEXT,
    rule_id TEXT,
    rule_level INTEGER,
    description TEXT,
    classification_confidence REAL,
    classification_severity TEXT,
    classification_source TEXT,
    priority TEXT,
    ioc_total INTEGER,
    ioc_hashes INTEGER,
    ioc_ips INTEGER,
    ioc_domains INTEGER,
    ioc_urls INTEGER,
    decision_engine_score REAL,
    decision_engine_details TEXT,
    misp_score REAL,
    misp_risk TEXT,
    misp_statistics TEXT,
    cortex_score REAL,
    cortex_risk TEXT,
    cortex_statistics TEXT,
    malicious_iocs INTEGER,
    final_score REAL,
    decision TEXT,
    risk_level TEXT,
    response_required INTEGER,
    label TEXT,
    label_source TEXT,
    labeled_at TEXT,
    occurrence_count INTEGER DEFAULT 1,
    last_seen_at TEXT,
    ml_prediction TEXT,
    ml_confidence REAL,
    ml_proba_true_positive REAL,
    ml_confidence_level TEXT,
    ml_model_version TEXT,
    ml_disagreement INTEGER DEFAULT 0,
    ml_disagreement_severity TEXT
);

CREATE TABLE IF NOT EXISTS alert_labels (
    fingerprint TEXT PRIMARY KEY,
    rule_id TEXT,
    incident_type TEXT,
    hostname TEXT,
    label TEXT,
    occurrences INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT
);
"""


def init_db():

    with sqlite3.connect(DB_PATH) as conn:

        conn.executescript(SCHEMA)

        existing_cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(incidents)"
            )
        }

        if "occurrence_count" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN occurrence_count INTEGER DEFAULT 1"
            )

        if "last_seen_at" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN last_seen_at TEXT"
            )

        if "ml_prediction" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_prediction TEXT"
            )

        if "ml_confidence" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_confidence REAL"
            )

        if "ml_proba_true_positive" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_proba_true_positive REAL"
            )

        if "ml_confidence_level" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_confidence_level TEXT"
            )

        if "ml_model_version" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_model_version TEXT"
            )

        if "ml_disagreement" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_disagreement INTEGER DEFAULT 0"
            )

        if "ml_disagreement_severity" not in existing_cols:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN ml_disagreement_severity TEXT"
            )

        conn.commit()

    print("[DB] incidents.db prête.")


def find_recent_duplicate(
    rule_id,
    incident_type,
    hostname,
    window_seconds=DUPLICATE_WINDOW_SECONDS
):

    with sqlite3.connect(DB_PATH) as conn:

        conn.row_factory = sqlite3.Row

        cur = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE rule_id = ?
              AND hostname = ?
              AND (
                    incident_type IS ?
                    OR incident_type = ?
                  )
              AND datetime(created_at) >=
                  datetime('now', ?)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (
                rule_id,
                hostname,
                incident_type,
                incident_type,
                f"-{window_seconds} seconds"
            )
        )

        row = cur.fetchone()

        return dict(row) if row else None


def find_by_fingerprint(
    rule_id,
    incident_type,
    hostname
):

    with sqlite3.connect(DB_PATH) as conn:

        conn.row_factory = sqlite3.Row

        cur = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE rule_id = ?
              AND hostname = ?
              AND (
                    incident_type IS ?
                    OR incident_type = ?
                  )
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (
                rule_id,
                hostname,
                incident_type,
                incident_type
            )
        )

        row = cur.fetchone()

        return dict(row) if row else None


def bump_duplicate(
    incident_id,
    final_score,
    decision
):

    with _lock:

        with sqlite3.connect(DB_PATH) as conn:

            conn.execute(
                """
                UPDATE incidents
                SET occurrence_count =
                        COALESCE(occurrence_count, 1) + 1,
                    last_seen_at = ?,
                    final_score = ?,
                    decision = ?
                WHERE incident_id = ?
                """,
                (
                    datetime.utcnow().isoformat(),
                    final_score,
                    decision,
                    incident_id
                )
            )

            conn.commit()


def save_incident(
    normalized: dict,
    risk: dict,
    decision: dict,
    is_known_alert: bool = False,
    ml_result: dict = None
):

    rule_id = normalized.get("rule_id")
    incident_type = normalized.get("incident_type")
    hostname = normalized.get("hostname")

    decision_value = decision.get("decision")

    ml_result = ml_result or {}
    ml_analysis = (
        normalized.get("ml_analysis", {}) or {}
    )

    print(
        f"[DB] save_incident | "
        f"rule={rule_id} | "
        f"type={incident_type} | "
        f"host={hostname} | "
        f"known={is_known_alert} | "
        f"ml={ml_result.get('prediction')}"
    )

    if decision_value not in CRITICAL_DECISIONS:

        duplicate = None

        if is_known_alert:
            duplicate = find_by_fingerprint(rule_id, incident_type, hostname)
        else:
            duplicate = find_recent_duplicate(rule_id, incident_type, hostname)

        if duplicate:

            bump_duplicate(
                duplicate["incident_id"],
                risk.get("final_score"),
                decision_value
            )

            print("[DB] Doublon détecté :", duplicate["incident_id"])

            return {
                "deduplicated": True,
                "incident_id": duplicate["incident_id"],
                "occurrence_count": (
                    duplicate.get("occurrence_count", 1) + 1
                )
            }

    classification = (normalized.get("classification", {}) or {})
    ioc_stats = (normalized.get("ioc_statistics", {}) or {})
    de = (risk.get("decision_engine", {}) or {})
    misp = (risk.get("misp", {}) or {})
    cortex = (risk.get("cortex", {}) or {})

    now = datetime.utcnow().isoformat()

    row = (
        normalized.get("incident_id"),
        normalized.get("timestamp"),
        now,
        normalized.get("hostname"),
        normalized.get("agent_id"),
        normalized.get("platform"),
        normalized.get("incident_type"),
        normalized.get("rule_id"),
        normalized.get("rule_level"),
        normalized.get("description"),
        classification.get("confidence"),
        classification.get("severity"),
        classification.get("source"),
        (normalized.get("investigation_plan", {}) or {}).get("priority"),
        ioc_stats.get("total", 0),
        ioc_stats.get("hashes", 0),
        ioc_stats.get("ips", 0),
        ioc_stats.get("domains", 0),
        ioc_stats.get("urls", 0),
        de.get("score"),
        json.dumps(de.get("details", {})),
        misp.get("score"),
        misp.get("risk"),
        json.dumps(misp.get("statistics", {})),
        cortex.get("score"),
        cortex.get("risk"),
        json.dumps(cortex.get("statistics", {})),
        risk.get("malicious_iocs"),
        risk.get("final_score"),
        decision.get("decision"),
        decision.get("risk"),
        int(bool(decision.get("response_required"))),
        None,
        None,
        None,
        1,
        now,
        ml_result.get("prediction"),
        ml_result.get("confidence"),
        ml_result.get("proba_true_positive"),
        ml_result.get("confidence_level"),
        ml_result.get("model_version"),
        int(bool(ml_analysis.get("disagreement", False))),
        ml_analysis.get("severity")
    )

    with _lock:

        with sqlite3.connect(DB_PATH) as conn:

            conn.execute(
                """
                INSERT OR REPLACE INTO incidents
                VALUES (
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?
                )
                """,
                row
            )

            conn.commit()

    print("[DB] Nouvel incident sauvegardé :", normalized.get("incident_id"))

    return {
        "deduplicated": False,
        "incident_id": normalized.get("incident_id")
    }


def update_label(
    incident_id: str,
    label: str,
    source: str
):

    with _lock:

        with sqlite3.connect(DB_PATH) as conn:

            conn.execute(
                """
                UPDATE incidents
                SET label = ?,
                    label_source = ?,
                    labeled_at = ?
                WHERE incident_id = ?
                """,
                (
                    label,
                    source,
                    datetime.utcnow().isoformat(),
                    incident_id
                )
            )

            conn.commit()


def get_incident(incident_id: str):

    with sqlite3.connect(DB_PATH) as conn:

        conn.row_factory = sqlite3.Row

        cur = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )

        row = cur.fetchone()

        return dict(row) if row else None
def get_or_update_notification_throttle(
    fingerprint,
    window_seconds=300
):
    """
    Décide s'il faut envoyer une notification pour ce fingerprint,
    ou l'absorber dans un digest silencieux.

    Retourne (should_notify: bool, burst_count: int)
    """

    now = datetime.utcnow()
    now_iso = now.isoformat()

    with _lock:

        with sqlite3.connect(DB_PATH) as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_throttle (
                    fingerprint TEXT PRIMARY KEY,
                    last_notified_at TEXT,
                    pending_count INTEGER DEFAULT 0
                )
                """
            )

            row = conn.execute(
                """
                SELECT last_notified_at, pending_count
                FROM notification_throttle
                WHERE fingerprint = ?
                """,
                (fingerprint,)
            ).fetchone()

            if row is None:

                conn.execute(
                    """
                    INSERT INTO notification_throttle
                    (fingerprint, last_notified_at, pending_count)
                    VALUES (?, ?, 0)
                    """,
                    (fingerprint, now_iso)
                )

                conn.commit()

                return True, 1

            last_notified_at, pending_count = row

            last_dt = (
                datetime.fromisoformat(last_notified_at)
                if last_notified_at else None
            )

            elapsed = (
                (now - last_dt).total_seconds()
                if last_dt else window_seconds + 1
            )

            if elapsed >= window_seconds:

                total = pending_count + 1

                conn.execute(
                    """
                    UPDATE notification_throttle
                    SET last_notified_at = ?, pending_count = 0
                    WHERE fingerprint = ?
                    """,
                    (now_iso, fingerprint)
                )

                conn.commit()

                return True, total

            else:

                conn.execute(
                    """
                    UPDATE notification_throttle
                    SET pending_count = pending_count + 1
                    WHERE fingerprint = ?
                    """,
                    (fingerprint,)
                )

                conn.commit()

                return False, pending_count + 1