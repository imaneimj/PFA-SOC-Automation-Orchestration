import sqlite3

import pandas as pd

from ml.ml_config import (
    MIN_DATASET_SIZE,
    FEATURES
)


DB_PATH = "/app/incidents.db"

TARGET = "label"


def load_dataset():

    conn = sqlite3.connect(
        DB_PATH
    )

    query = """
        SELECT
            rule_level,
            classification_confidence,
            ioc_total,
            ioc_hashes,
            ioc_ips,
            ioc_domains,
            ioc_urls,
            decision_engine_score,
            misp_score,
            cortex_score,
            malicious_iocs,
            label,
            label_source,
            occurrence_count
        FROM incidents
        WHERE label IN (
            'TRUE_POSITIVE',
            'FALSE_POSITIVE'
        )
        AND label_source = 'analyst'
    """

    df = pd.read_sql_query(
        query,
        conn
    )

    conn.close()

    if df.empty:

        raise ValueError(
            "Aucun incident labellisé par un analyste."
        )

    df = df.drop_duplicates()

    df["label"] = df[
        "label"
    ].map(
        {
            "FALSE_POSITIVE": 0,
            "TRUE_POSITIVE": 1
        }
    )

    df = df.dropna(
        subset=["label"]
    )

    return df


def prepare_dataset():

    df = load_dataset()

    X = (
        df[FEATURES]
        .fillna(0)
        .astype(float)
    )

    y = df[
        TARGET
    ].astype(int)

    return X, y


if __name__ == "__main__":

    df = load_dataset()

    print(
        "=" * 70
    )

    print(
        "ML DATASET"
    )

    print(
        "=" * 70
    )

    print(
        f"Nombre d'incidents : {len(df)}"
    )

    print(
        "\nLabels :"
    )

    print(
        df["label"].value_counts()
    )

    print(
        "\nFeatures :"
    )

    for feature in FEATURES:

        print(
            f" - {feature}"
        )