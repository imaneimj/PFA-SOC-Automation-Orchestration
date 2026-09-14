import sqlite3
import pandas as pd
from ml.ml_config import FEATURES

DB_PATH="/app/incidents.db"
TARGET="label"

def load_dataset():
    conn=sqlite3.connect(DB_PATH)
    query="""
        SELECT
            incident_id,
            rule_id,
            description,
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
            occurrence_count,
            created_at
        FROM incidents
        WHERE label IN (
            'TRUE_POSITIVE',
            'FALSE_POSITIVE'
        )
        AND label_source='analyst'
    """
    df=pd.read_sql_query(query,conn)
    conn.close()

    if df.empty:
        raise ValueError("Aucun incident labellisé par un analyste.")

    for feature in FEATURES:
        if feature not in df.columns:
            raise ValueError(f"Feature absente de la DB : {feature}")
        df[feature]=pd.to_numeric(df[feature],errors="coerce").fillna(0)

    df["label"]=df["label"].map({
        "FALSE_POSITIVE":0,
        "TRUE_POSITIVE":1
    })

    df=df.dropna(subset=["label"])
    df["label"]=df["label"].astype(int)

    feature_columns=list(FEATURES)
    conflict_groups=df.groupby(feature_columns)["label"].nunique()
    conflicting_features=set(
        conflict_groups[conflict_groups>1].index
    )

    if conflicting_features:
        print("\n[ML] ATTENTION : conflits TP/FP détectés.")
        print(f"[ML] Vecteurs en conflit : {len(conflicting_features)}")
        for features in list(conflicting_features)[:10]:
            print("[ML] CONFLIT :",features)

    df=df.sort_values(
        by=["occurrence_count","created_at"],
        ascending=[False,True]
    )

    before=len(df)

    df=df.drop_duplicates(
        subset=feature_columns+["label"],
        keep="first"
    )

    removed=before-len(df)
    print(f"\n[ML] Doublons supprimés : {removed}")
    print(f"[ML] Exemples uniques : {len(df)}")

    conflict_check=df.groupby(feature_columns)["label"].nunique()
    remaining_conflicts=conflict_check[conflict_check>1]

    if len(remaining_conflicts)>0:
        print("\n[ML] ERREUR : conflits TP/FP encore présents après déduplication.")

    return df

def prepare_dataset():
    df=load_dataset()
    X=df[FEATURES].fillna(0).astype(float)
    y=df[TARGET].astype(int)
    return X,y

if __name__=="__main__":
    df=load_dataset()

    print("\n"+"="*70)
    print("ML DATASET")
    print("="*70)
    print(f"Nombre d'exemples uniques : {len(df)}")
    print("\nLabels :")
    print(df["label"].value_counts())
    print("\nFeatures :")

    for feature in FEATURES:
        print(f" - {feature}")

    print(
        "\nDoublons FEATURES + LABEL :",
        df.duplicated(
            subset=list(FEATURES)+["label"]
        ).sum()
    )