import sqlite3

from datetime import (
    datetime,
    timedelta
)

DB_PATH = "/app/incidents.db"


def calculate_learning_priority(
    ml_result,
    ml_analysis
):

    if not ml_result:
        return 0

    if not ml_result.get(
        "available",
        False
    ):
        return 0

    confidence = (
        ml_result.get(
            "confidence"
        )
        or 0
    )

    score = 0

    if confidence < 0.70:
        score += 40

    if ml_analysis.get(
        "disagreement",
        False
    ):
        score += 40

    if ml_analysis.get(
        "severity"
    ) == "HIGH":
        score += 20

    return min(
        score,
        100
    )


def calculate_ml_status(
    ml_result: dict
):

    if (
        not ml_result
        or not ml_result.get(
            "available",
            False
        )
    ):

        return {
            "status": "UNAVAILABLE",
            "model_version":
                (ml_result or {}).get(
                    "model_version"
                ),
            "reason":
                (ml_result or {}).get(
                    "reason",
                    "MODEL_UNAVAILABLE"
                )
        }

    confidence = (
        ml_result.get(
            "confidence"
        )
        or 0
    )

    if confidence >= 0.90:

        status = "READY"

    elif confidence >= 0.70:

        status = "DEGRADED"

    else:

        status = "LOW_CONFIDENCE"

    return {

        "status":
            status,

        "model_version":
            ml_result.get(
                "model_version"
            ),

        "confidence":
            confidence,

        "confidence_level":
            ml_result.get(
                "confidence_level"
            )
    }


def analyze_ml_rule_agreement(
    window_hours: int = 24
):

    since = (
        datetime.utcnow()
        - timedelta(
            hours=window_hours
        )
    ).isoformat()

    try:

        with sqlite3.connect(
            DB_PATH
        ) as conn:

            cur = conn.execute(
                """
                SELECT
                    ml_disagreement,
                    ml_disagreement_severity
                FROM incidents
                WHERE created_at >= ?
                  AND ml_prediction IS NOT NULL
                """,
                (since,)
            )

            rows = cur.fetchall()

    except sqlite3.Error:

        return {
            "window_hours":
                window_hours,

            "total_scored":
                0,

            "agreement_rate":
                None,

            "disagreement_count":
                0,

            "high_severity_disagreements":
                0,

            "error":
                "DATABASE_ERROR"
        }

    total = len(
        rows
    )

    if total == 0:

        return {

            "window_hours":
                window_hours,

            "total_scored":
                0,

            "agreement_rate":
                None,

            "disagreement_count":
                0,

            "high_severity_disagreements":
                0
        }

    disagreements = sum(
        1
        for row in rows
        if bool(row[0])
    )

    high_severity = sum(
        1
        for row in rows
        if row[1] == "HIGH"
    )

    agreement_rate = (
        1
        - (
            disagreements
            / total
        )
    )

    return {

        "window_hours":
            window_hours,

        "total_scored":
            total,

        "agreement_rate":
            round(
                agreement_rate,
                4
            ),

        "disagreement_count":
            disagreements,

        "high_severity_disagreements":
            high_severity
    }