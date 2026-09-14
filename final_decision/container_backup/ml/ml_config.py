import os


MODEL_PATH = os.getenv(
    "ML_MODEL_PATH",
    "/app/ml/model.pkl"
)


MODEL_VERSION = os.getenv(
    "ML_MODEL_VERSION",
    "1.0.0"
)


MIN_DATASET_SIZE = int(
    os.getenv(
        "ML_MIN_DATASET_SIZE",
        "30"
    )
)


MIN_SAMPLES_PER_CLASS = int(
    os.getenv(
        "ML_MIN_SAMPLES_PER_CLASS",
        "10"
    )
)


HIGH_CONFIDENCE_THRESHOLD = float(
    os.getenv(
        "ML_HIGH_CONFIDENCE_THRESHOLD",
        "0.90"
    )
)


MEDIUM_CONFIDENCE_THRESHOLD = float(
    os.getenv(
        "ML_MEDIUM_CONFIDENCE_THRESHOLD",
        "0.70"
    )
)


DISAGREEMENT_HIGH_CONFIDENCE = float(
    os.getenv(
        "ML_DISAGREEMENT_HIGH_CONFIDENCE",
        "0.90"
    )
)


FEATURES = [
    "rule_level",
    "classification_confidence",
    "ioc_total",
    "ioc_hashes",
    "ioc_ips",
    "ioc_domains",
    "ioc_urls",
    "decision_engine_score",
    "misp_score",
    "cortex_score",
    "malicious_iocs"
]