import sqlite3
import sys
from datetime import datetime
from collections import defaultdict
DB_PATH = "incidents.db"
DUPLICATE_WINDOW_SECONDS = 300
CRITICAL_DECISIONS = {
    "AUTO_CONTAIN",
    "AUTO_RESPONSE",
    "ANALYST_APPROVAL"}
def parse_ts(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
def main(apply_changes: bool):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT incident_id, rule_id, incident_type, hostname,
               created_at, decision, occurrence_count
        FROM incidents
        ORDER BY rule_id, hostname, incident_type, created_at ASC
        """).fetchall()
    groups = defaultdict(list)
    for r in rows:
        key = (r["rule_id"], r["incident_type"], r["hostname"])
        groups[key].append(dict(r))

    to_delete = []
    to_update = []  

    for key, items in groups.items():
        cluster = []
        def flush_cluster(cluster):
            if len(cluster) <= 1:
                return
            if any(it["decision"] in CRITICAL_DECISIONS for it in cluster):
                return
            keep = cluster[-1]  
            total_occurrences = sum(
                it.get("occurrence_count") or 1 for it in cluster)
            to_update.append((keep["incident_id"], total_occurrences))
            for it in cluster[:-1]:
                to_delete.append(it["incident_id"])
        prev_ts = None
        for item in items:
            ts = parse_ts(item["created_at"])
            if prev_ts is None or ts is None:
                cluster = [item]
            else:
                delta = (ts - prev_ts).total_seconds()
                if delta <= DUPLICATE_WINDOW_SECONDS:
                    cluster.append(item)
                else:
                    flush_cluster(cluster)
                    cluster = [item]
            prev_ts = ts
        flush_cluster(cluster)
    print(f"Incidents totaux       : {len(rows)}")
    print(f"Incidents à supprimer  : {len(to_delete)}")
    print(f"Incidents à mettre à jour (occurrence_count) : {len(to_update)}")
    if not apply_changes:
        print("\n[DRY-RUN] Aucune modification appliquée. "
              "Relance avec --apply pour exécuter réellement.")
        conn.close()
        return
    with conn:
        for incident_id, occ in to_update:
            conn.execute(
                "UPDATE incidents SET occurrence_count = ? WHERE incident_id = ?",
                (occ, incident_id),
            )
        for incident_id in to_delete:
            conn.execute(
                "DELETE FROM incidents WHERE incident_id = ?",
                (incident_id,),
            )

    print("\n[OK] Nettoyage appliqué.")
    conn.close()


if __name__ == "__main__":
    apply_changes = "--apply" in sys.argv
    main(apply_changes)