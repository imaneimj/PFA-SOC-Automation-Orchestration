import os
import shutil
import sqlite3
from datetime import datetime
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)
from ml.dataset import prepare_dataset,DB_PATH
from ml.ml_config import (
    MODEL_PATH,
    MODEL_BACKUP_PATH,
    MODEL_VERSION,
    MIN_DATASET_SIZE,
    MIN_SAMPLES_PER_CLASS,
    F1_REGRESSION_TOLERANCE,
    F1_CHECK_MIN_DATASET_SIZE
)

def _ensure_training_log_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ml_training_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            triggered_at TEXT NOT NULL,
            triggered_by TEXT,
            dataset_size INTEGER,
            accuracy REAL,
            precision_score REAL,
            recall REAL,
            f1 REAL,
            roc_auc REAL,
            promoted INTEGER NOT NULL,
            rejection_reason TEXT,
            model_version TEXT,
            last_label_event_id INTEGER
        )
        """
    )
    existing_cols={
        row[1]
        for row in conn.execute("PRAGMA table_info(ml_training_log)")
    }
    if "last_label_event_id" not in existing_cols:
        conn.execute(
            "ALTER TABLE ml_training_log ADD COLUMN last_label_event_id INTEGER"
        )
    conn.commit()

def _log_training(
    conn,
    dataset_size,
    metadata,
    promoted,
    rejection_reason,
    triggered_by,
    last_label_event_id
):
    _ensure_training_log_table(conn)
    conn.execute(
        """
        INSERT INTO ml_training_log (
            triggered_at,triggered_by,dataset_size,
            accuracy,precision_score,recall,f1,roc_auc,
            promoted,rejection_reason,model_version,
            last_label_event_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            datetime.utcnow().isoformat(),
            triggered_by,
            dataset_size,
            metadata["accuracy"],
            metadata["precision"],
            metadata["recall"],
            metadata["f1"],
            metadata["roc_auc"],
            int(promoted),
            rejection_reason,
            metadata["model_version"],
            last_label_event_id
        )
    )
    conn.commit()

def _load_previous_f1():
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        bundle=joblib.load(MODEL_PATH)
        if isinstance(bundle,dict):
            return bundle.get("metadata",{}).get("f1")
    except Exception:
        return None
    return None

def _get_max_label_event_id(conn):
    try:
        row=conn.execute(
            "SELECT COALESCE(MAX(id),0) FROM label_events"
        ).fetchone()
        return row[0] or 0
    except sqlite3.OperationalError:
        return 0

def train(triggered_by="manual",up_to_label_event_id=None):
    X,y=prepare_dataset()

    print("="*70)
    print("ML TRAINING")
    print("="*70)
    print(f"Dataset total : {len(X)}")

    class_counts=y.value_counts()

    print("\nRépartition :")
    print(class_counts)

    if len(X)<MIN_DATASET_SIZE:
        raise ValueError(
            f"Dataset insuffisant : {len(X)} < {MIN_DATASET_SIZE}"
        )

    for label in [0,1]:
        count=int(class_counts.get(label,0))
        if count<MIN_SAMPLES_PER_CLASS:
            raise ValueError(
                f"Classe {label} insuffisante : {count} samples."
            )

    X_train,X_test,y_train,y_test=train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    model=RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train,y_train)

    predictions=model.predict(X_test)
    probabilities=model.predict_proba(X_test)[:,1]

    accuracy=accuracy_score(y_test,predictions)
    precision=precision_score(y_test,predictions,zero_division=0)
    recall=recall_score(y_test,predictions,zero_division=0)
    f1=f1_score(y_test,predictions,zero_division=0)

    try:
        roc_auc=roc_auc_score(y_test,probabilities)
    except ValueError:
        roc_auc=None

    print("\n==============================")
    print("MODEL PERFORMANCE")
    print("==============================")
    print(f"Accuracy  : {accuracy:.3f}")
    print(f"Precision : {precision:.3f}")
    print(f"Recall    : {recall:.3f}")
    print(f"F1        : {f1:.3f}")

    if roc_auc is not None:
        print(f"ROC-AUC   : {roc_auc:.3f}")

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["FALSE_POSITIVE","TRUE_POSITIVE"],
            zero_division=0
        )
    )

    print("\nConfusion matrix:")
    print(confusion_matrix(y_test,predictions))

    metadata={
        "model_version":MODEL_VERSION,
        "features":list(X.columns),
        "dataset_size":int(len(X)),
        "training_size":int(len(X_train)),
        "test_size":int(len(X_test)),
        "accuracy":float(accuracy),
        "precision":float(precision),
        "recall":float(recall),
        "f1":float(f1),
        "roc_auc":float(roc_auc) if roc_auc is not None else None
    }

    bundle={
        "model":model,
        "metadata":metadata
    }

    model_directory=os.path.dirname(MODEL_PATH)
    os.makedirs(model_directory,exist_ok=True)

    previous_f1=_load_previous_f1()
    promote=True
    rejection_reason=None

    if (
        len(X)>=F1_CHECK_MIN_DATASET_SIZE
        and previous_f1 is not None
        and f1<previous_f1-F1_REGRESSION_TOLERANCE
    ):
        promote=False
        rejection_reason=(
            f"F1 candidat {f1:.3f} < F1 actuel {previous_f1:.3f} "
            f"(tolérance {F1_REGRESSION_TOLERANCE})"
        )

    elif (
        len(X)<F1_CHECK_MIN_DATASET_SIZE
        and previous_f1 is not None
        and f1<previous_f1-F1_REGRESSION_TOLERANCE
    ):
        print(
            f"\n[ML] F1 en baisse ({f1:.3f} < {previous_f1:.3f}) "
            f"mais dataset encore petit ({len(X)} < "
            f"{F1_CHECK_MIN_DATASET_SIZE}) : garde-fou ignoré, "
            f"promotion quand même."
        )

    conn=sqlite3.connect(DB_PATH)

    last_label_event_id=(
        up_to_label_event_id
        if up_to_label_event_id is not None
        else _get_max_label_event_id(conn)
    )

    if promote:
        if os.path.exists(MODEL_PATH):
            shutil.copy2(MODEL_PATH,MODEL_BACKUP_PATH)

        joblib.dump(bundle,MODEL_PATH)

        print(f"\n[ML] Modèle promu : {MODEL_PATH}")
        print(f"[ML] Version : {MODEL_VERSION}")

    else:
        print(f"\n[ML] Modèle candidat REJETÉ : {rejection_reason}")
        print("[ML] Ancien modèle conservé.")

    _log_training(
        conn,
        dataset_size=len(X),
        metadata=metadata,
        promoted=promote,
        rejection_reason=rejection_reason,
        triggered_by=triggered_by,
        last_label_event_id=last_label_event_id
    )

    conn.close()

    return {
        "promoted":promote,
        "rejection_reason":rejection_reason,
        "metadata":metadata,
        "last_label_event_id":last_label_event_id
    }

if __name__=="__main__":
    train(triggered_by="manual_cli")