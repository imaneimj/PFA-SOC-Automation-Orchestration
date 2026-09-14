from datetime import datetime
import ipaddress
from db import DB_PATH
from db_utils import get_connection
from config import ZERO_DAY_BASELINE

LEARNING_MIN_EVENTS=ZERO_DAY_BASELINE.get("learning_min_events",20)
MATURE_MIN_EVENTS=ZERO_DAY_BASELINE.get("mature_min_events",100)
ESTABLISHED_BEHAVIOR_OCCURRENCES=ZERO_DAY_BASELINE.get("established_behavior_occurrences",3)
MIN_DISTINCT_DAYS_BEFORE_TRUST=ZERO_DAY_BASELINE.get("min_distinct_days_before_trust",3)

def _safe(value):
    if value is None:
        return ""
    return str(value).strip().lower()

def _safe_port(value):
    if value is None:
        return -1
    try:
        return int(value)
    except (TypeError,ValueError):
        return -1

def _is_ip(value):
    if not value:
        return False
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False

def get_baseline_status(hostname):
    if not hostname:
        return {
            "total_events":0,
            "quality":"LEARNING",
            "first_seen":None,
            "last_seen":None
        }

    conn=get_connection(DB_PATH)
    try:
        row=conn.execute(
            """
            SELECT total_events,first_seen,last_seen
            FROM behavior_statistics
            WHERE hostname=?
            """,
            (hostname,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return {
            "total_events":0,
            "quality":"LEARNING",
            "first_seen":None,
            "last_seen":None
        }

    total_events=int(row[0] or 0)

    if total_events<LEARNING_MIN_EVENTS:
        quality="LEARNING"
    elif total_events<MATURE_MIN_EVENTS:
        quality="WEAK"
    else:
        quality="MATURE"

    return {
        "total_events":total_events,
        "quality":quality,
        "first_seen":row[1],
        "last_seen":row[2]
    }

def find_matching_behavior(hostname,behavior):
    if not hostname:
        return {
            "known":False,
            "occurrences":0,
            "first_seen":None,
            "last_seen":None
        }

    behavior=behavior or {}
    port=_safe_port(behavior.get("destination_port"))
    conn=get_connection(DB_PATH)

    try:
        row=conn.execute(
            """
            SELECT occurrences,first_seen,last_seen
            FROM behavior_baselines
            WHERE hostname=?
              AND process_name=?
              AND parent_process=?
              AND destination=?
              AND destination_port=?
              AND protocol=?
              AND command_pattern=?
            LIMIT 1
            """,
            (
                hostname,
                _safe(behavior.get("process_name")),
                _safe(behavior.get("parent_process")),
                _safe(behavior.get("destination")),
                port,
                _safe(behavior.get("protocol")),
                _safe(behavior.get("command_pattern"))
            )
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return {
            "known":False,
            "occurrences":0,
            "first_seen":None,
            "last_seen":None
        }

    return {
        "known":True,
        "occurrences":int(row[0] or 0),
        "first_seen":row[1],
        "last_seen":row[2]
    }

def _find_process_behavior(hostname,process_name):
    if not hostname or not process_name:
        return False

    conn=get_connection(DB_PATH)
    try:
        row=conn.execute(
            """
            SELECT 1
            FROM behavior_baselines
            WHERE hostname=? AND process_name=?
            LIMIT 1
            """,
            (hostname,_safe(process_name))
        ).fetchone()
    finally:
        conn.close()

    return row is not None

def _find_parent_child(hostname,process_name,parent_process):
    if not hostname or not process_name or not parent_process:
        return False

    conn=get_connection(DB_PATH)
    try:
        row=conn.execute(
            """
            SELECT 1
            FROM behavior_baselines
            WHERE hostname=?
              AND process_name=?
              AND parent_process=?
            LIMIT 1
            """,
            (
                hostname,
                _safe(process_name),
                _safe(parent_process)
            )
        ).fetchone()
    finally:
        conn.close()

    return row is not None

def _find_destination(hostname,destination):
    if not hostname or not destination:
        return False

    conn=get_connection(DB_PATH)
    try:
        row=conn.execute(
            """
            SELECT 1
            FROM behavior_baselines
            WHERE hostname=? AND destination=?
            LIMIT 1
            """,
            (hostname,_safe(destination))
        ).fetchone()
    finally:
        conn.close()

    return row is not None

def _find_port(hostname,port):
    if not hostname:
        return False

    port=_safe_port(port)

    if port==-1:
        return False

    conn=get_connection(DB_PATH)
    try:
        row=conn.execute(
            """
            SELECT 1
            FROM behavior_baselines
            WHERE hostname=?
              AND destination_port=?
              AND destination IS NOT NULL
              AND destination!=''
            LIMIT 1
            """,
            (hostname,port)
        ).fetchone()
    finally:
        conn.close()

    return row is not None

def _has_multi_day_history(first_seen,last_seen):
    if not first_seen or not last_seen:
        return False

    try:
        first=datetime.fromisoformat(str(first_seen))
        last=datetime.fromisoformat(str(last_seen))
        delta_days=(last.date()-first.date()).days
        return delta_days>=max(0,MIN_DISTINCT_DAYS_BEFORE_TRUST-1)
    except (TypeError,ValueError):
        return False

def analyze_behavior(hostname,behavior):
    behavior=behavior or {}
    baseline=get_baseline_status(hostname)
    exact_match=find_matching_behavior(hostname,behavior)
    indicators=[]
    reasons=[]
    novelty_score=0
    anomaly_score=0

    process_name=_safe(behavior.get("process_name"))
    parent_process=_safe(behavior.get("parent_process"))
    destination=_safe(behavior.get("destination"))
    port=_safe_port(behavior.get("destination_port"))
    protocol=_safe(behavior.get("protocol"))
    command_pattern=_safe(behavior.get("command_pattern"))

    if exact_match["known"]:
        occurrences=exact_match["occurrences"]
        established=occurrences>=ESTABLISHED_BEHAVIOR_OCCURRENCES
        multi_day=_has_multi_day_history(
            exact_match["first_seen"],
            exact_match["last_seen"]
        )

        if not established:
            novelty_score+=10
            indicators.append("RARE_BEHAVIOR")
            reasons.append(
                "Le comportement existe dans la baseline "
                "mais reste peu fréquent."
            )
        elif MIN_DISTINCT_DAYS_BEFORE_TRUST>1 and not multi_day:
            novelty_score+=5
            indicators.append("BEHAVIOR_HISTORY_NOT_MATURE")
            reasons.append(
                "Le comportement possède suffisamment "
                "d'occurrences mais son historique "
                "ne couvre pas encore suffisamment de jours."
            )
    else:
        novelty_score+=35
        indicators.append("NEW_BEHAVIOR_FINGERPRINT")
        reasons.append(
            "La combinaison comportementale complète "
            "n'a jamais été observée sur cet endpoint."
        )

    process_known=_find_process_behavior(
        hostname,
        process_name
    )
    new_process=bool(process_name) and not process_known

    if new_process:
        novelty_score+=20
        indicators.append("NEW_PROCESS")
        reasons.append(
            f"Le processus '{process_name}' "
            "n'a jamais été observé dans la baseline "
            "de cet endpoint."
        )

    parent_child_known=_find_parent_child(
        hostname,
        process_name,
        parent_process
    )
    new_parent_child=(
        bool(process_name)
        and bool(parent_process)
        and not parent_child_known
    )

    if new_parent_child:
        novelty_score+=20
        indicators.append("NEW_PARENT_CHILD_RELATION")
        reasons.append(
            f"La relation '{parent_process}' -> "
            f"'{process_name}' n'a jamais été observée "
            "dans la baseline."
        )

    destination_known=_find_destination(
        hostname,
        destination
    )
    new_destination=bool(destination) and not destination_known

    if new_destination:
        novelty_score+=15
        indicators.append("NEW_DESTINATION")
        reasons.append(
            f"La destination '{destination}' "
            "n'a jamais été observée dans la baseline."
        )

    destination_is_ip=_is_ip(destination)
    new_ip=new_destination and destination_is_ip
    new_domain=(
        new_destination
        and bool(destination)
        and not destination_is_ip
    )

    if new_ip:
        indicators.append("NEW_IP")
        reasons.append(
            f"L'adresse IP '{destination}' "
            "n'a jamais été observée dans la baseline."
        )

    if new_domain:
        indicators.append("NEW_DOMAIN")
        reasons.append(
            f"Le domaine '{destination}' "
            "n'a jamais été observé dans la baseline."
        )

    port_known=_find_port(hostname,port)
    new_port=(
        port!=-1
        and bool(destination)
        and not port_known
    )

    if new_port:
        novelty_score+=10
        indicators.append("NEW_DESTINATION_PORT")
        reasons.append(
            f"Le port '{port}' "
            "n'a jamais été observé dans la baseline."
        )

    observable_fields=sum(
        bool(value)
        for value in (
            process_name,
            parent_process,
            destination,
            protocol,
            command_pattern
        )
    )

    if observable_fields==0:
        indicators.append("INSUFFICIENT_BEHAVIORAL_DATA")
        reasons.append(
            "Les données comportementales disponibles "
            "sont insuffisantes pour une comparaison fiable."
        )
        novelty_score=0
        anomaly_score=0
    else:
        if not exact_match["known"]:
            anomaly_score+=40
        if new_process:
            anomaly_score+=15
        if new_parent_child:
            anomaly_score+=20
        if new_destination:
            anomaly_score+=10
        if new_port:
            anomaly_score+=10

        if (
            exact_match["known"]
            and exact_match["occurrences"]>=ESTABLISHED_BEHAVIOR_OCCURRENCES
        ):
            anomaly_score=0

    novelty_score=min(int(novelty_score),100)
    anomaly_score=min(int(anomaly_score),100)

    return {
        "novelty_score":novelty_score,
        "anomaly_score":anomaly_score,
        "new_behavior":not exact_match["known"],
        "behavior_known":exact_match["known"],
        "behavior_occurrences":exact_match["occurrences"],
        "process_known":process_known,
        "new_process":new_process,
        "parent_child_known":parent_child_known,
        "new_parent_child":new_parent_child,
        "destination_known":destination_known,
        "new_destination":new_destination,
        "destination_is_ip":destination_is_ip,
        "new_ip":new_ip,
        "new_domain":new_domain,
        "port_known":port_known,
        "new_port":new_port,
        "protocol":protocol,
        "baseline_quality":baseline["quality"],
        "baseline_events":baseline["total_events"],
        "baseline_first_seen":baseline["first_seen"],
        "baseline_last_seen":baseline["last_seen"],
        "data_quality":"GOOD" if observable_fields>=3 else "LIMITED",
        "indicators":list(dict.fromkeys(indicators)),
        "reasons":list(dict.fromkeys(reasons))
    }

def update_baseline(hostname,behavior,allow_learning=True):
    if not hostname:
        return {
            "updated":False,
            "reason":"missing_hostname"
        }

    if not allow_learning:
        return {
            "updated":False,
            "reason":"learning_blocked"
        }

    behavior=behavior or {}
    now=datetime.utcnow().isoformat()
    port=_safe_port(behavior.get("destination_port"))
    conn=get_connection(DB_PATH)

    try:
        conn.execute(
            """
            INSERT INTO behavior_baselines (
                hostname,
                process_name,
                parent_process,
                destination,
                destination_port,
                protocol,
                command_pattern,
                occurrences,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(
                hostname,
                process_name,
                parent_process,
                destination,
                destination_port,
                protocol,
                command_pattern
            )
            DO UPDATE SET
                occurrences=occurrences+1,
                last_seen=excluded.last_seen
            """,
            (
                hostname,
                _safe(behavior.get("process_name")),
                _safe(behavior.get("parent_process")),
                _safe(behavior.get("destination")),
                port,
                _safe(behavior.get("protocol")),
                _safe(behavior.get("command_pattern")),
                now,
                now
            )
        )

        conn.execute(
            """
            INSERT INTO behavior_statistics (
                hostname,
                total_events,
                first_seen,
                last_seen,
                baseline_quality
            )
            VALUES (?, 1, ?, ?, 'LEARNING')
            ON CONFLICT(hostname)
            DO UPDATE SET
                total_events=total_events+1,
                last_seen=excluded.last_seen,
                baseline_quality=
                    CASE
                        WHEN total_events+1 < ?
                            THEN 'LEARNING'
                        WHEN total_events+1 < ?
                            THEN 'WEAK'
                        ELSE 'MATURE'
                    END
            """,
            (
                hostname,
                now,
                now,
                LEARNING_MIN_EVENTS,
                MATURE_MIN_EVENTS
            )
        )

        conn.commit()
    finally:
        conn.close()

    return {
        "updated":True,
        "reason":"baseline_updated"
    }

def should_update_baseline(
    zero_day_score,
    decision,
    zero_day_suspected=False,
    malicious_iocs=0
):
    try:
        zero_day_score=float(zero_day_score or 0)
    except (TypeError,ValueError):
        zero_day_score=0

    try:
        malicious_iocs=int(malicious_iocs or 0)
    except (TypeError,ValueError):
        malicious_iocs=0

    decision=_safe(decision).upper()

    if zero_day_suspected:
        return False

    if malicious_iocs>0:
        return False

    safe_learning_score=ZERO_DAY_BASELINE.get(
        "safe_learning_max_score",
        25
    )

    if zero_day_score>safe_learning_score:
        return False

    blocked_decisions={
        "AUTO_CONTAIN",
        "AUTO_RESPONSE",
        "ANALYST_APPROVAL",
        "KNOWN_TRUE_POSITIVE"
    }

    if decision in blocked_decisions:
        return False

    safe_decisions={
        "MONITOR",
        "IGNORE",
        "IGNORED",
        "BENIGN",
        "NO_ACTION",
        "MONITORING"
    }

    if decision in safe_decisions:
        return True

    return False