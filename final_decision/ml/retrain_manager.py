import os
import sqlite3
import threading
import time
import logging
from datetime import datetime,timedelta
from ml.ml_config import (
    MIN_NEW_LABELS_FOR_RETRAIN,
    RETRAIN_COOLDOWN_MINUTES,
    TRAINING_LOCK_PATH,
    TRAINING_LOCK_MAX_AGE_SECONDS
)
from ml.dataset import DB_PATH
from ml.train import train

logger=logging.getLogger("MLRetrain")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s - %(message)s"
    )

def _get_max_label_event_id():
    conn=sqlite3.connect(DB_PATH)
    try:
        row=conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM label_events"
        ).fetchone()
        return row[0] or 0
    except sqlite3.OperationalError:
        return 0
    finally:
        conn.close()

def _last_training_info():
    conn=sqlite3.connect(DB_PATH)
    try:
        cur=conn.execute(
            """
            SELECT triggered_at,last_label_event_id
            FROM ml_training_log
            ORDER BY id DESC
            LIMIT 1
            """
        )
        row=cur.fetchone()
    except sqlite3.OperationalError:
        row=None
    conn.close()

    if row is None:
        return None,0

    triggered_at,last_event_id=row

    return datetime.fromisoformat(triggered_at),last_event_id or 0

def _acquire_lock():
    if os.path.exists(TRAINING_LOCK_PATH):
        age=time.time()-os.path.getmtime(TRAINING_LOCK_PATH)

        if age<TRAINING_LOCK_MAX_AGE_SECONDS:
            return False

        logger.warning(
            "[ML] Verrou périmé détecté (%.0fs), il est ignoré.",
            age
        )

    with open(TRAINING_LOCK_PATH,"w") as f:
        f.write(str(os.getpid()))

    return True

def _release_lock():
    try:
        os.remove(TRAINING_LOCK_PATH)
    except FileNotFoundError:
        pass

def _run_training(triggered_by,up_to_label_event_id):
    try:
        result=train(
            triggered_by=triggered_by,
            up_to_label_event_id=up_to_label_event_id
        )

        logger.info(
            "[ML] Entraînement terminé : promu=%s f1=%.3f (jusqu'à label_event_id=%s)",
            result["promoted"],
            result["metadata"]["f1"],
            up_to_label_event_id
        )

    except ValueError as e:
        logger.warning("[ML] Entraînement annulé : %s",e)

    except Exception:
        logger.exception("[ML] Erreur pendant l'entraînement")

    finally:
        _release_lock()

def maybe_retrain_async(triggered_by="analyst_label"):
    last_time,last_event_id=_last_training_info()
    current_event_id=_get_max_label_event_id()
    new_labels=current_event_id-last_event_id

    if new_labels<MIN_NEW_LABELS_FOR_RETRAIN:
        logger.info(
            "[ML] Pas assez de nouvelles actions de labellisation (%d < %d), pas de réentraînement.",
            new_labels,
            MIN_NEW_LABELS_FOR_RETRAIN
        )
        return

    if last_time is not None:
        cooldown_end=last_time+timedelta(minutes=RETRAIN_COOLDOWN_MINUTES)

        if datetime.utcnow()<cooldown_end:
            logger.info(
                "[ML] Cooldown actif jusqu'à %s, pas de réentraînement.",
                cooldown_end.isoformat()
            )
            return

    if not _acquire_lock():
        logger.info("[ML] Entraînement déjà en cours, on saute.")
        return

    snapshot_event_id=current_event_id

    thread=threading.Thread(
        target=_run_training,
        args=(triggered_by,snapshot_event_id),
        daemon=True
    )

    thread.start()

if __name__=="__main__":
    maybe_retrain_async(triggered_by="manual_cli")