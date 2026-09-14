import sqlite3
import json
import threading
from datetime import datetime

DB_PATH="/app/incidents.db"

_lock=threading.Lock()

CRITICAL_DECISIONS={
    "AUTO_CONTAIN",
    "AUTO_RESPONSE",
    "ANALYST_APPROVAL"
}

DUPLICATE_WINDOW_SECONDS=300

SCHEMA="""
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
    zero_day_score REAL,
    zero_day_risk TEXT,
    zero_day_confidence REAL,
    zero_day_suspected INTEGER DEFAULT 0,
    zero_day_indicators TEXT,
    zero_day_reasons TEXT,
    zero_day_components TEXT,
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

CREATE TABLE IF NOT EXISTS behavior_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    process_name TEXT,
    parent_process TEXT,
    destination TEXT,
    destination_port INTEGER,
    protocol TEXT,
    command_pattern TEXT,
    occurrences INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE(
        hostname,
        process_name,
        parent_process,
        destination,
        destination_port,
        protocol,
        command_pattern
    )
);

CREATE TABLE IF NOT EXISTS behavior_statistics (
    hostname TEXT PRIMARY KEY,
    total_events INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    baseline_quality TEXT DEFAULT 'LEARNING'
);

CREATE TABLE IF NOT EXISTS label_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    label TEXT NOT NULL,
    source TEXT NOT NULL,
    previous_label TEXT,
    event_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_label_events_event_at
    ON label_events(event_at);

CREATE TABLE IF NOT EXISTS fleet_behavior_baselines (
    fingerprint TEXT PRIMARY KEY,
    hosts_seen INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT
);
"""

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)

        existing_cols={
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(incidents)"
            )
        }

        migrations={
            "occurrence_count":
                "ALTER TABLE incidents ADD COLUMN occurrence_count INTEGER DEFAULT 1",
            "last_seen_at":
                "ALTER TABLE incidents ADD COLUMN last_seen_at TEXT",
            "ml_prediction":
                "ALTER TABLE incidents ADD COLUMN ml_prediction TEXT",
            "ml_confidence":
                "ALTER TABLE incidents ADD COLUMN ml_confidence REAL",
            "ml_proba_true_positive":
                "ALTER TABLE incidents ADD COLUMN ml_proba_true_positive REAL",
            "ml_confidence_level":
                "ALTER TABLE incidents ADD COLUMN ml_confidence_level TEXT",
            "ml_model_version":
                "ALTER TABLE incidents ADD COLUMN ml_model_version TEXT",
            "ml_disagreement":
                "ALTER TABLE incidents ADD COLUMN ml_disagreement INTEGER DEFAULT 0",
            "ml_disagreement_severity":
                "ALTER TABLE incidents ADD COLUMN ml_disagreement_severity TEXT",
            "zero_day_score":
                "ALTER TABLE incidents ADD COLUMN zero_day_score REAL",
            "zero_day_risk":
                "ALTER TABLE incidents ADD COLUMN zero_day_risk TEXT",
            "zero_day_confidence":
                "ALTER TABLE incidents ADD COLUMN zero_day_confidence REAL",
            "zero_day_suspected":
                "ALTER TABLE incidents ADD COLUMN zero_day_suspected INTEGER DEFAULT 0",
            "zero_day_indicators":
                "ALTER TABLE incidents ADD COLUMN zero_day_indicators TEXT",
            "zero_day_reasons":
                "ALTER TABLE incidents ADD COLUMN zero_day_reasons TEXT",
            "zero_day_components":
                "ALTER TABLE incidents ADD COLUMN zero_day_components TEXT",
            "zero_day_novelty_score":
                "ALTER TABLE incidents ADD COLUMN zero_day_novelty_score REAL",
            "zero_day_anomaly_score":
                "ALTER TABLE incidents ADD COLUMN zero_day_anomaly_score REAL",
            "zero_day_baseline_quality":
                "ALTER TABLE incidents ADD COLUMN zero_day_baseline_quality TEXT",
            "zero_day_baseline_events":
                "ALTER TABLE incidents ADD COLUMN zero_day_baseline_events INTEGER",
            "zero_day_behavior_fingerprint":
                "ALTER TABLE incidents ADD COLUMN zero_day_behavior_fingerprint TEXT"
        }

        for column,statement in migrations.items():
            if column not in existing_cols:
                conn.execute(statement)

        conn.commit()

    print("[DB] incidents.db prête.")

def find_recent_duplicate(
    rule_id,
    incident_type,
    hostname,
    window_seconds=DUPLICATE_WINDOW_SECONDS
):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory=sqlite3.Row

        cur=conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE rule_id=?
              AND hostname=?
              AND (
                    incident_type IS ?
                    OR incident_type=?
                  )
              AND datetime(created_at)>=
                  datetime('now',?)
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

        row=cur.fetchone()
        return dict(row) if row else None

def find_by_fingerprint(
    rule_id,
    incident_type,
    hostname
):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory=sqlite3.Row

        cur=conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE rule_id=?
              AND hostname=?
              AND (
                    incident_type IS ?
                    OR incident_type=?
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

        row=cur.fetchone()
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
                SET occurrence_count=
                        COALESCE(occurrence_count,1)+1,
                    last_seen_at=?,
                    final_score=?,
                    decision=?
                WHERE incident_id=?
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
    normalized:dict,
    risk:dict,
    decision:dict,
    is_known_alert:bool=False,
    ml_result:dict=None
):
    normalized=normalized or {}
    risk=risk or {}
    decision=decision or {}
    ml_result=ml_result or {}

    rule_id=normalized.get("rule_id")
    incident_type=normalized.get("incident_type")
    hostname=normalized.get("hostname")
    decision_value=decision.get("decision")

    ml_analysis=(
        normalized.get("ml_analysis",{})
        or {}
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
        duplicate=None

        if is_known_alert:
            duplicate=find_by_fingerprint(
                rule_id,
                incident_type,
                hostname
            )
        else:
            duplicate=find_recent_duplicate(
                rule_id,
                incident_type,
                hostname
            )

        if duplicate:
            bump_duplicate(
                duplicate["incident_id"],
                risk.get("final_score"),
                decision_value
            )

            print(
                "[DB] Doublon détecté :",
                duplicate["incident_id"]
            )

            return {
                "deduplicated":True,
                "incident_id":duplicate["incident_id"],
                "occurrence_count":(
                    duplicate.get("occurrence_count",1)+1
                )
            }

    classification=(
        normalized.get("classification",{})
        or {}
    )

    ioc_stats=(
        normalized.get("ioc_statistics",{})
        or {}
    )

    de=(
        risk.get("decision_engine",{})
        or {}
    )

    misp=(
        risk.get("misp",{})
        or {}
    )

    cortex=(
        risk.get("cortex",{})
        or {}
    )

    zero_day=(
        risk.get("zero_day",{})
        or {}
    )

    zero_day_score=zero_day.get("score",0)
    zero_day_risk=zero_day.get("risk","LOW")
    zero_day_confidence=zero_day.get("confidence",0)
    zero_day_suspected=int(
        bool(zero_day.get("suspected",False))
    )

    zero_day_indicators=json.dumps(
        zero_day.get("indicators",[])
    )

    zero_day_reasons=json.dumps(
        zero_day.get("reasons",[])
    )

    zero_day_components=json.dumps(
        zero_day.get("components",{})
    )

    zero_day_novelty_score=zero_day.get(
        "novelty_score",
        0
    )

    zero_day_anomaly_score=zero_day.get(
        "anomaly_score",
        0
    )

    zero_day_baseline=(
        zero_day.get("baseline",{})
        or {}
    )

    zero_day_baseline_quality=zero_day_baseline.get(
        "quality",
        "UNKNOWN"
    )

    zero_day_baseline_events=zero_day_baseline.get(
        "events",
        0
    )

    zero_day_behavior_fingerprint=zero_day.get(
        "behavior_fingerprint"
    )

    now=datetime.utcnow().isoformat()

    columns=[
        "incident_id",
        "timestamp",
        "created_at",
        "hostname",
        "agent_id",
        "platform",
        "incident_type",
        "rule_id",
        "rule_level",
        "description",
        "classification_confidence",
        "classification_severity",
        "classification_source",
        "priority",
        "ioc_total",
        "ioc_hashes",
        "ioc_ips",
        "ioc_domains",
        "ioc_urls",
        "decision_engine_score",
        "decision_engine_details",
        "misp_score",
        "misp_risk",
        "misp_statistics",
        "cortex_score",
        "cortex_risk",
        "cortex_statistics",
        "zero_day_score",
        "zero_day_risk",
        "zero_day_confidence",
        "zero_day_suspected",
        "zero_day_indicators",
        "zero_day_reasons",
        "zero_day_components",
        "zero_day_novelty_score",
        "zero_day_anomaly_score",
        "zero_day_baseline_quality",
        "zero_day_baseline_events",
        "zero_day_behavior_fingerprint",
        "malicious_iocs",
        "final_score",
        "decision",
        "risk_level",
        "response_required",
        "label",
        "label_source",
        "labeled_at",
        "occurrence_count",
        "last_seen_at",
        "ml_prediction",
        "ml_confidence",
        "ml_proba_true_positive",
        "ml_confidence_level",
        "ml_model_version",
        "ml_disagreement",
        "ml_disagreement_severity"
    ]

    values=(
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
        (
            normalized.get("investigation_plan",{})
            or {}
        ).get("priority"),
        ioc_stats.get("total",0),
        ioc_stats.get("hashes",0),
        ioc_stats.get("ips",0),
        ioc_stats.get("domains",0),
        ioc_stats.get("urls",0),
        de.get("score"),
        json.dumps(de.get("details",{})),
        misp.get("score"),
        misp.get("risk"),
        json.dumps(misp.get("statistics",{})),
        cortex.get("score"),
        cortex.get("risk"),
        json.dumps(cortex.get("statistics",{})),
        zero_day_score,
        zero_day_risk,
        zero_day_confidence,
        zero_day_suspected,
        zero_day_indicators,
        zero_day_reasons,
        zero_day_components,
        zero_day_novelty_score,
        zero_day_anomaly_score,
        zero_day_baseline_quality,
        zero_day_baseline_events,
        zero_day_behavior_fingerprint,
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
        int(bool(ml_analysis.get("disagreement",False))),
        ml_analysis.get("severity")
    )

    if len(columns)!=len(values):
        raise RuntimeError(
            f"DB columns/values mismatch: "
            f"{len(columns)} columns vs {len(values)} values"
        )

    placeholders=",".join(["?"]*len(values))

    sql=f"""
        INSERT OR REPLACE INTO incidents (
            {",".join(columns)}
        )
        VALUES (
            {placeholders}
        )
    """

    with _lock:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(sql,values)
            conn.commit()

    print(
        "[DB] Nouvel incident sauvegardé :",
        normalized.get("incident_id")
    )

    return {
        "deduplicated":False,
        "incident_id":normalized.get("incident_id")
    }

def update_label(
    incident_id:str,
    label:str,
    source:str
):
    now=datetime.utcnow().isoformat()

    with _lock:
        with sqlite3.connect(DB_PATH) as conn:
            row=conn.execute(
                """
                SELECT label
                FROM incidents
                WHERE incident_id=?
                """,
                (incident_id,)
            ).fetchone()

            previous_label=row[0] if row else None

            conn.execute(
                """
                UPDATE incidents
                SET label=?,
                    label_source=?,
                    labeled_at=?
                WHERE incident_id=?
                """,
                (
                    label,
                    source,
                    now,
                    incident_id
                )
            )

            conn.execute(
                """
                INSERT INTO label_events (
                    incident_id,
                    label,
                    source,
                    previous_label,
                    event_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    label,
                    source,
                    previous_label,
                    now
                )
            )

            conn.commit()

    changed=previous_label!=label

    print(
        f"[DB] update_label | incident={incident_id} | "
        f"{previous_label!r} -> {label!r} | "
        f"changed={changed}"
    )

    def demote_fingerprint_on_false_positive(
        fingerprint,
        hostname
    ):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                UPDATE behavior_baselines
                SET occurrences=occurrences+5
                WHERE hostname=?
                  AND fingerprint_hint=?
                """,
                (hostname,fingerprint)
            )

    return {
        "incident_id":incident_id,
        "label":label,
        "previous_label":previous_label,
        "changed":changed
    }

def get_max_label_event_id()->int:
    with sqlite3.connect(DB_PATH) as conn:
        row=conn.execute(
            "SELECT COALESCE(MAX(id),0) FROM label_events"
        ).fetchone()

        return row[0] or 0

def get_incident(incident_id:str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory=sqlite3.Row

        cur=conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE incident_id=?
            """,
            (incident_id,)
        )

        row=cur.fetchone()
        return dict(row) if row else None

def get_or_update_notification_throttle(
    fingerprint,
    window_seconds=300
):
    now=datetime.utcnow()
    now_iso=now.isoformat()

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

            row=conn.execute(
                """
                SELECT last_notified_at,pending_count
                FROM notification_throttle
                WHERE fingerprint=?
                """,
                (fingerprint,)
            ).fetchone()

            if row is None:
                conn.execute(
                    """
                    INSERT INTO notification_throttle (
                        fingerprint,
                        last_notified_at,
                        pending_count
                    )
                    VALUES (?, ?, 0)
                    """,
                    (
                        fingerprint,
                        now_iso
                    )
                )

                conn.commit()
                return True,1

            last_notified_at,pending_count=row

            last_dt=(
                datetime.fromisoformat(last_notified_at)
                if last_notified_at
                else None
            )

            elapsed=(
                (now-last_dt).total_seconds()
                if last_dt
                else window_seconds+1
            )

            if elapsed>=window_seconds:
                total=pending_count+1

                conn.execute(
                    """
                    UPDATE notification_throttle
                    SET last_notified_at=?,
                        pending_count=0
                    WHERE fingerprint=?
                    """,
                    (
                        now_iso,
                        fingerprint
                    )
                )

                conn.commit()
                return True,total

            conn.execute(
                """
                UPDATE notification_throttle
                SET pending_count=pending_count+1
                WHERE fingerprint=?
                """,
                (fingerprint,)
            )

            conn.commit()

            return False,pending_count+1