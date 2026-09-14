import os

MODEL_PATH=os.getenv("ML_MODEL_PATH","/app/ml/model.pkl")
MODEL_BACKUP_PATH=os.getenv("ML_MODEL_BACKUP_PATH","/app/ml/model_previous.pkl")
MODEL_VERSION=os.getenv("ML_MODEL_VERSION","1.0.0")

MIN_DATASET_SIZE=int(os.getenv("ML_MIN_DATASET_SIZE","6"))
MIN_SAMPLES_PER_CLASS=int(os.getenv("ML_MIN_SAMPLES_PER_CLASS","3"))

HIGH_CONFIDENCE_THRESHOLD=float(os.getenv("ML_HIGH_CONFIDENCE_THRESHOLD","0.90"))
MEDIUM_CONFIDENCE_THRESHOLD=float(os.getenv("ML_MEDIUM_CONFIDENCE_THRESHOLD","0.70"))
DISAGREEMENT_HIGH_CONFIDENCE=float(os.getenv("ML_DISAGREEMENT_HIGH_CONFIDENCE","0.90"))

MIN_NEW_LABELS_FOR_RETRAIN=int(os.getenv("ML_MIN_NEW_LABELS_FOR_RETRAIN","5"))
RETRAIN_COOLDOWN_MINUTES=int(os.getenv("ML_RETRAIN_COOLDOWN_MINUTES","30"))
F1_REGRESSION_TOLERANCE=float(os.getenv("ML_F1_REGRESSION_TOLERANCE","0.05"))

TRAINING_LOCK_PATH=os.getenv("ML_TRAINING_LOCK_PATH","/app/ml/.training.lock")
TRAINING_LOCK_MAX_AGE_SECONDS=int(os.getenv("ML_TRAINING_LOCK_MAX_AGE_SECONDS","600"))

FEATURES=[
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

F1_CHECK_MIN_DATASET_SIZE=int(
    os.getenv("ML_F1_CHECK_MIN_DATASET_SIZE","30")
)