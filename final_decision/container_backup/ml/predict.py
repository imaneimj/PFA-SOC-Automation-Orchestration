import os
import logging

import joblib
import numpy as np
import pandas as pd

from ml.ml_config import (
    MODEL_PATH,
    MODEL_VERSION,
    HIGH_CONFIDENCE_THRESHOLD,
    MEDIUM_CONFIDENCE_THRESHOLD,
    FEATURES
)


logger = logging.getLogger(
    "MLPredict"
)


if not logger.handlers:

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s - %(message)s"
    )


_model_cache = {
    "model": None,
    "mtime": None,
    "metadata": {}
}


def _empty_result(
    reason="MODEL_UNAVAILABLE"
):

    return {

        "available":
            False,

        "prediction":
            None,

        "confidence":
            None,

        "proba_true_positive":
            None,

        "confidence_level":
            "UNAVAILABLE",

        "model_version":
            MODEL_VERSION,

        "model_status":
            "UNAVAILABLE",

        "reason":
            reason,

        "features":
            FEATURES
    }


def _load_model():

    if not os.path.exists(
        MODEL_PATH
    ):

        logger.info(
            "[ML] Modèle absent : %s",
            MODEL_PATH
        )

        return None

    try:

        mtime = os.path.getmtime(
            MODEL_PATH
        )

        if (
            _model_cache["model"] is None
            or _model_cache["mtime"] != mtime
        ):

            bundle = joblib.load(
                MODEL_PATH
            )

            if isinstance(
                bundle,
                dict
            ):

                model = bundle.get(
                    "model"
                )

                metadata = bundle.get(
                    "metadata",
                    {}
                )

            else:

                model = bundle
                metadata = {}

            if model is None:

                logger.warning(
                    "[ML] Bundle invalide."
                )

                return None

            _model_cache["model"] = model
            _model_cache["mtime"] = mtime
            _model_cache["metadata"] = metadata

            logger.info(
                "[ML] Modèle chargé : %s",
                MODEL_PATH
            )

        return _model_cache["model"]

    except Exception as e:

        logger.exception(
            "[ML] Erreur chargement modèle : %s",
            e
        )

        return None


def _extract_features(
    normalized: dict,
    risk: dict
):

    risk = risk or {}

    classification = (
        normalized.get(
            "classification",
            {}
        )
        or {}
    )

    ioc_stats = (
        normalized.get(
            "ioc_statistics",
            {}
        )
        or {}
    )

    decision_engine = (
        risk.get(
            "decision_engine",
            {}
        )
        or {}
    )

    misp = (
        risk.get(
            "misp",
            {}
        )
        or {}
    )

    cortex = (
        risk.get(
            "cortex",
            {}
        )
        or {}
    )

    values = {

        "rule_level":
            normalized.get(
                "rule_level"
            ),

        "classification_confidence":
            classification.get(
                "confidence"
            ),

        "ioc_total":
            ioc_stats.get(
                "total",
                0
            ),

        "ioc_hashes":
            ioc_stats.get(
                "hashes",
                0
            ),

        "ioc_ips":
            ioc_stats.get(
                "ips",
                0
            ),

        "ioc_domains":
            ioc_stats.get(
                "domains",
                0
            ),

        "ioc_urls":
            ioc_stats.get(
                "urls",
                0
            ),

        "decision_engine_score":
            decision_engine.get(
                "score"
            ),

        "misp_score":
            misp.get(
                "score"
            ),

        "cortex_score":
            cortex.get(
                "score"
            ),

        "malicious_iocs":
            risk.get(
                "malicious_iocs"
            )
    }

    result = {}

    for feature in FEATURES:

        value = values.get(
            feature,
            0
        )

        try:

            result[feature] = float(
                value
                if value is not None
                else 0
            )

        except (
            TypeError,
            ValueError
        ):

            result[feature] = 0.0

    return result


def predict(
    normalized: dict,
    risk: dict = None
):

    model = _load_model()

    if model is None:

        return _empty_result(
            "MODEL_UNAVAILABLE"
        )

    try:

        feature_values = _extract_features(
            normalized,
            risk
        )

        X = pd.DataFrame(
            [feature_values],
            columns=FEATURES
        )

        X = X.fillna(0).astype(float)

        probabilities = model.predict_proba(
            X
        )[0]

        classes = list(
            model.classes_
        )

        if 1 not in classes:

            return _empty_result(
                "TRUE_POSITIVE_CLASS_MISSING"
            )

        tp_index = classes.index(
            1
        )

        proba_tp = float(
            probabilities[tp_index]
        )

        confidence = float(
            np.max(
                probabilities
            )
        )

        if confidence >= HIGH_CONFIDENCE_THRESHOLD:

            confidence_level = "HIGH"

        elif confidence >= MEDIUM_CONFIDENCE_THRESHOLD:

            confidence_level = "MEDIUM"

        else:

            confidence_level = "LOW"

        prediction = (
            "TRUE_POSITIVE"
            if proba_tp >= 0.5
            else "FALSE_POSITIVE"
        )

        return {

            "available":
                True,

            "prediction":
                prediction,

            "confidence":
                round(
                    confidence,
                    3
                ),

            "proba_true_positive":
                round(
                    proba_tp,
                    3
                ),

            "confidence_level":
                confidence_level,

            "model_version":
                MODEL_VERSION,

            "model_status":
                "READY",

            "features":
                FEATURES,

            "model_metadata":
                _model_cache.get(
                    "metadata",
                    {}
                )
        }

    except Exception as e:

        logger.exception(
            "[ML] Prediction error"
        )

        return _empty_result(
            "PREDICTION_ERROR"
        )