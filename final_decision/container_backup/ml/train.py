import os

import joblib

from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import (
    train_test_split
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)

from ml.dataset import (
    prepare_dataset
)

from ml.ml_config import (
    MODEL_PATH,
    MODEL_VERSION,
    MIN_DATASET_SIZE,
    MIN_SAMPLES_PER_CLASS
)


def train():

    X, y = prepare_dataset()

    print(
        "=" * 70
    )

    print(
        "ML TRAINING"
    )

    print(
        "=" * 70
    )

    print(
        f"Dataset total : {len(X)}"
    )

    class_counts = y.value_counts()

    print(
        "\nRépartition :"
    )

    print(
        class_counts
    )

    if len(X) < MIN_DATASET_SIZE:

        raise ValueError(
            f"Dataset insuffisant : "
            f"{len(X)} < {MIN_DATASET_SIZE}"
        )

    for label in [0, 1]:

        count = int(
            class_counts.get(
                label,
                0
            )
        )

        if count < MIN_SAMPLES_PER_CLASS:

            raise ValueError(
                f"Classe {label} insuffisante : "
                f"{count} samples."
            )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y
        )
    )

    model = RandomForestClassifier(

        n_estimators=300,

        max_depth=12,

        min_samples_leaf=2,

        class_weight="balanced",

        random_state=42,

        n_jobs=-1
    )

    model.fit(
        X_train,
        y_train
    )

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    try:

        roc_auc = roc_auc_score(
            y_test,
            probabilities
        )

    except ValueError:

        roc_auc = None

    print(
        "\n=============================="
    )

    print(
        "MODEL PERFORMANCE"
    )

    print(
        "=============================="
    )

    print(
        f"Accuracy  : {accuracy:.3f}"
    )

    print(
        f"Precision : {precision:.3f}"
    )

    print(
        f"Recall    : {recall:.3f}"
    )

    print(
        f"F1        : {f1:.3f}"
    )

    if roc_auc is not None:

        print(
            f"ROC-AUC   : {roc_auc:.3f}"
        )

    print(
        "\nClassification report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "FALSE_POSITIVE",
                "TRUE_POSITIVE"
            ],
            zero_division=0
        )
    )

    print(
        "\nConfusion matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    metadata = {

        "model_version":
            MODEL_VERSION,

        "features":
            list(
                X.columns
            ),

        "dataset_size":
            int(
                len(X)
            ),

        "training_size":
            int(
                len(X_train)
            ),

        "test_size":
            int(
                len(X_test)
            ),

        "accuracy":
            float(
                accuracy
            ),

        "precision":
            float(
                precision
            ),

        "recall":
            float(
                recall
            ),

        "f1":
            float(
                f1
            ),

        "roc_auc":
            (
                float(
                    roc_auc
                )
                if roc_auc is not None
                else None
            )
    }

    bundle = {

        "model":
            model,

        "metadata":
            metadata
    }

    model_directory = os.path.dirname(
        MODEL_PATH
    )

    os.makedirs(
        model_directory,
        exist_ok=True
    )

    joblib.dump(
        bundle,
        MODEL_PATH
    )

    print(
        f"\n[ML] Model saved : {MODEL_PATH}"
    )

    print(
        f"[ML] Version : {MODEL_VERSION}"
    )


if __name__ == "__main__":

    train()