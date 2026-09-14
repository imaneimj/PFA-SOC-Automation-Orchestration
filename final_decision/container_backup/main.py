# /app/main.py

from fastapi import (
    FastAPI,
    Request
)

from fastapi.responses import JSONResponse

import traceback


from db import (
    init_db,
    save_incident,
    update_label,
    get_or_update_notification_throttle
)


from alert_memory import (
    get_known_label,
    save_label,
    build_fingerprint
)


from scoring.final_scoring import (
    calculate_final_score
)


from decision.decision_logic import (
    make_decision
)


from decision.response_engine import (
    build_response
)


from ml.predict import (
    predict as ml_predict
)


from ml_status import (
    calculate_learning_priority,
    calculate_ml_status,
    analyze_ml_rule_agreement
)


from zero_day.behavioral_fingerprint import (
    build_behavior_fingerprint
)


from zero_day.behavioral_baseline import (
    update_baseline,
    should_update_baseline
)


app = FastAPI(
    title="Final Decision Engine",
    version="1.4.0"
)


# ==========================================================
# STARTUP
# ==========================================================

@app.on_event("startup")
async def startup():

    init_db()


# ==========================================================
# ROOT
# ==========================================================

@app.get("/")
async def root():

    return {
        "service": "Final Decision Engine",
        "version": "1.4.0",
        "status": "running"
    }


# ==========================================================
# HEALTH
# ==========================================================

@app.get("/health")
async def health():

    return {
        "status": "healthy"
    }


# ==========================================================
# ML ANALYSIS
# ==========================================================

def _build_ml_analysis(
    decision_value,
    ml_result
):
    """
    Compare la décision des règles avec la prédiction ML.

    IMPORTANT :
    Le ML reste consultatif.

    Il ne modifie jamais directement
    la décision du moteur.
    """

    if not ml_result.get(
        "available",
        False
    ):

        return {
            "disagreement": False,
            "severity": "NONE",
            "learning_priority": 0
        }


    rules_says_positive = (
        decision_value
        in {
            "AUTO_CONTAIN",
            "AUTO_RESPONSE",
            "ANALYST_APPROVAL",
            "KNOWN_TRUE_POSITIVE"
        }
    )


    ml_says_positive = (
        ml_result.get(
            "prediction"
        )
        ==
        "TRUE_POSITIVE"
    )


    disagreement = (
        rules_says_positive
        !=
        ml_says_positive
    )


    if (
        disagreement
        and
        ml_result.get(
            "confidence_level"
        )
        ==
        "HIGH"
    ):

        severity = "HIGH"

    elif disagreement:

        severity = "MEDIUM"

    else:

        severity = "NONE"


    analysis = {

        "disagreement":
            disagreement,

        "severity":
            severity
    }


    analysis["learning_priority"] = (
        calculate_learning_priority(
            ml_result,
            analysis
        )
    )


    return analysis


# ==========================================================
# FINALIZE
# ==========================================================

@app.post("/finalize")
async def finalize(
    request: Request
):

    try:

        payload = await request.json()


        # ==================================================
        # 1. INPUT
        # ==================================================

        normalized = (
            payload.get(
                "normalized",
                {}
            )
            or {}
        )


        misp = (
            payload.get(
                "misp",
                []
            )
            or []
        )


        cortex = (
            payload.get(
                "cortex",
                []
            )
            or []
        )


        # ==================================================
        # 2. ALERT MEMORY
        # ==================================================

        known = get_known_label(
            normalized
        )


        # ==================================================
        # 3. FINAL RISK SCORING
        # ==================================================

        risk = calculate_final_score(
            normalized,
            misp,
            cortex
        )


        # ==================================================
        # 4. DECISION
        # ==================================================

        if (
            known["known"]
            and
            known["occurrences"] >= 3
        ):

            if (
                known["label"]
                ==
                "TRUE_POSITIVE"
            ):

                decision = {

                    "decision":
                        "KNOWN_TRUE_POSITIVE",

                    "risk":
                        "High",

                    "response_required":
                        True,

                    "analyst_approval_required":
                        False
                }

            else:

                decision = {

                    "decision":
                        "KNOWN_FALSE_POSITIVE",

                    "risk":
                        "Low",

                    "response_required":
                        False,

                    "analyst_approval_required":
                        False
                }

        else:

            decision = make_decision(
                risk["final_score"],
                incident_type=
                    normalized.get(
                        "incident_type",
                        ""
                    ),
                malicious_iocs=
                    risk["malicious_iocs"]
            )


        # ==================================================
        # 5. ZERO-DAY / BEHAVIORAL BASELINE
        # ==================================================

        zero_day_result = (
            risk.get(
                "zero_day",
                {}
            )
            or {}
        )


        zero_day_score = (
            zero_day_result.get(
                "score",
                0
            )
        )


        zero_day_suspected = (
            zero_day_result.get(
                "suspected",
                False
            )
        )


        # --------------------------------------------------
        # Déterminer si le nouvel événement peut
        # alimenter la baseline comportementale.
        # --------------------------------------------------

        allow_baseline_learning = (
            should_update_baseline(
                zero_day_score,
                decision.get(
                    "decision"
                ),
                zero_day_suspected
            )
        )


        # --------------------------------------------------
        # Construire le fingerprint comportemental
        # --------------------------------------------------

        behavior = build_behavior_fingerprint(
            normalized
        )


        # --------------------------------------------------
        # Mise à jour baseline
        # --------------------------------------------------

        baseline_update = update_baseline(
            normalized.get(
                "hostname"
            ),
            behavior,
            allow_learning=
                allow_baseline_learning
        )


        print(
            "[ZERO-DAY] Baseline learning:",
            baseline_update
        )


        # ==================================================
        # 6. MACHINE LEARNING
        # ==================================================

        ml_result = ml_predict(
            normalized,
            risk
        )


        ml_analysis = _build_ml_analysis(
            decision["decision"],
            ml_result
        )


        # Le ML est ajouté au contexte.
        # Il ne remplace jamais la décision.

        normalized["ml_analysis"] = (
            ml_analysis
        )


        # ==================================================
        # 7. RESPONSE ENGINE
        # ==================================================

        response = build_response(
            decision["decision"],
            normalized,
            risk,
            ml_result
        )


        # ==================================================
        # 8. DATABASE
        # ==================================================

        db_result = save_incident(
            normalized,
            risk,
            decision,
            is_known_alert=
                known["known"],
            ml_result=
                ml_result
        )


        # ==================================================
        # 9. NOTIFICATION THROTTLE
        # ==================================================

        fingerprint = build_fingerprint(
            normalized
        )


        (
            should_notify,
            burst_count
        ) = get_or_update_notification_throttle(
            fingerprint,
            window_seconds=300
        )


        # --------------------------------------------------
        # Notification forcée dans certains cas
        # --------------------------------------------------

        force_notify = (

            ml_analysis.get(
                "severity"
            )
            ==
            "HIGH"

            or

            decision.get(
                "analyst_approval_required",
                False
            )

            or

            (
                risk
                .get(
                    "zero_day",
                    {}
                )
                .get(
                    "suspected",
                    False
                )
            )
        )


        # --------------------------------------------------
        # Suppression notification si throttle actif
        # --------------------------------------------------

        if (
            not should_notify
            and
            not force_notify
        ):

            response["actions"] = [

                action

                for action in response.get(
                    "actions",
                    []
                )

                if action.get(
                    "tool"
                )
                !=
                "notification"
            ]


        else:

            for action in response.get(
                "actions",
                []
            ):

                if (
                    action.get(
                        "tool"
                    )
                    ==
                    "notification"
                ):

                    context = action.setdefault(
                        "context",
                        {}
                    )


                    context[
                        "burst_count"
                    ] = burst_count


                    if (
                        force_notify
                        and
                        not should_notify
                    ):

                        context[
                            "throttle_override"
                        ] = (
                            "SECURITY_ENRICHMENT"
                        )


        response["throttled"] = (
            not should_notify
            and
            not force_notify
        )


        response["burst_count"] = (
            burst_count
        )


        # ==================================================
        # 10. API RESPONSE
        # ==================================================

        return JSONResponse({

            "success":
                True,

            "risk":
                risk,

            "decision":
                decision,

            "ml": {

                "result":
                    ml_result,

                "analysis":
                    ml_analysis
            },

            "known_alert":
                known,

            "response":
                response,

            "db":
                db_result
        })


    except Exception as e:

        traceback.print_exc()


        return JSONResponse(

            status_code=500,

            content={

                "success":
                    False,

                "error":
                    str(e)
            }
        )


# ==========================================================
# ANALYST LABEL
# ==========================================================

@app.post("/label")
async def label(
    request: Request
):

    """
    Feedback analyste.

    Le label alimente :

    1. incidents.db
    2. alert_labels
    3. mémoire comportementale

    Le feedback pourra ensuite servir
    au réentraînement ML.
    """

    try:

        payload = await request.json()


        incident_id = payload.get(
            "incident_id"
        )


        lbl = payload.get(
            "label"
        )


        normalized = (
            payload.get(
                "normalized",
                {}
            )
            or {}
        )


        if (
            not incident_id
            or
            lbl not in {
                "TRUE_POSITIVE",
                "FALSE_POSITIVE"
            }
        ):

            return JSONResponse(

                status_code=400,

                content={

                    "success":
                        False,

                    "error":
                        (
                            "incident_id and "
                            "a valid label "
                            "are required."
                        )
                }
            )


        # --------------------------------------------------
        # DB
        # --------------------------------------------------

        update_label(
            incident_id,
            lbl,
            source="analyst"
        )


        # --------------------------------------------------
        # Alert Memory
        # --------------------------------------------------

        memory_result = save_label(
            normalized,
            lbl
        )


        return JSONResponse({

            "success":
                True,

            "incident_id":
                incident_id,

            "label":
                lbl,

            "memory":
                memory_result
        })


    except Exception as e:

        traceback.print_exc()


        return JSONResponse(

            status_code=500,

            content={

                "success":
                    False,

                "error":
                    str(e)
            }
        )


# ==========================================================
# ML STATUS
# ==========================================================

@app.get("/ml/status")
async def ml_status():

    try:

        probe = ml_predict(
            {},
            {}
        )


        return calculate_ml_status(
            probe
        )


    except Exception as e:

        return JSONResponse(

            status_code=500,

            content={

                "success":
                    False,

                "error":
                    str(e)
            }
        )


# ==========================================================
# ML AGREEMENT
# ==========================================================

@app.get("/ml/agreement")
async def ml_agreement(
    window_hours: int = 24
):

    try:

        return analyze_ml_rule_agreement(
            window_hours
        )


    except Exception as e:

        return JSONResponse(

            status_code=500,

            content={

                "success":
                    False,

                "error":
                    str(e)
            }
        )