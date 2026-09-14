from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse,HTMLResponse
import requests
import traceback
import os
import sqlite3
import html

from report_generator import generate_complete_report
from ml.ml_config import MODEL_PATH
from ml.train import train
from ml.predict import predict as ml_predict
from ml import retrain_manager
from ml_status import (
    calculate_learning_priority,
    calculate_ml_status,
    analyze_ml_rule_agreement
)

RESPONSE_ENGINE_URL=os.getenv(
    "RESPONSE_ENGINE_URL",
    "http://response-engine:8095"
).rstrip("/")

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

from scoring.final_scoring import calculate_final_score
from decision.decision_logic import make_decision
from decision.response_engine import build_response
from zero_day.behavioral_fingerprint import build_behavior_fingerprint
from zero_day.behavioral_baseline import (
    update_baseline,
    should_update_baseline
)

app=FastAPI(
    title="Final Decision Engine",
    version="1.4.0"
)

def ensure_ml_model():
    if os.path.exists(MODEL_PATH):
        print(f"[ML] Model already exists: {MODEL_PATH}")
        return True

    print(f"[ML] Model not found: {MODEL_PATH}")
    print("[ML] Attempting automatic training...")

    try:
        result=train()

        if os.path.exists(MODEL_PATH):
            print(
                f"[ML] Model successfully generated: "
                f"{MODEL_PATH}"
            )
            return True

        print(
            "[ML] Training completed "
            "but model was not generated."
        )
        print("[ML] Dataset may still be insufficient.")
        return False

    except Exception as e:
        print(f"[ML] Automatic training unavailable: {e}")
        traceback.print_exc()
        return False

@app.on_event("startup")
async def startup():
    init_db()
    ensure_ml_model()

@app.get("/")
async def root():
    return {
        "service":"Final Decision Engine",
        "version":"1.4.0",
        "status":"running"
    }

@app.get("/health")
async def health():
    return {"status":"healthy"}

def _build_ml_analysis(
    decision_value,
    ml_result,
    known_status=None
):
    if not ml_result.get("available",False):
        return {
            "disagreement":False,
            "severity":"NONE",
            "learning_priority":0
        }

    rules_says_positive=(
        decision_value in {"AUTO_CONTAIN","AUTO_RESPONSE"}
        or known_status=="KNOWN_TRUE_POSITIVE"
    )

    ml_says_positive=(
        ml_result.get("prediction")=="TRUE_POSITIVE"
    )

    disagreement=(
        rules_says_positive!=ml_says_positive
    )

    if disagreement and ml_result.get(
        "confidence_level"
    )=="HIGH":
        severity="HIGH"
    elif disagreement:
        severity="MEDIUM"
    else:
        severity="NONE"

    analysis={
        "disagreement":disagreement,
        "severity":severity
    }

    analysis["learning_priority"]=calculate_learning_priority(
        ml_result,
        analysis
    )

    return analysis

@app.post("/finalize")
async def finalize(request:Request):
    try:
        payload=await request.json()

        normalized=(
            payload.get("normalized",{})
            or {}
        )

        misp=(
            payload.get("misp",[])
            or []
        )

        cortex=(
            payload.get("cortex",[])
            or []
        )

        known=get_known_label(normalized)

        risk=calculate_final_score(
            normalized,
            misp,
            cortex
        )

        decision=make_decision(
            risk["final_score"],
            incident_type=normalized.get(
                "incident_type",
                ""
            ),
            malicious_iocs=risk["malicious_iocs"]
        )

        decision["known_alert"]=known.get("known",False)
        decision["known_label"]=known.get("label")
        decision["known_occurrences"]=known.get(
            "occurrences",
            0
        )

        if (
            known.get("known",False)
            and known.get("occurrences",0)>=3
            and known.get("label")=="TRUE_POSITIVE"
        ):
            decision["known_status"]="KNOWN_TRUE_POSITIVE"
            print(
                "[ALERT MEMORY] Known TRUE_POSITIVE detected "
                "but rule-based decision remains PRIORITY:",
                decision["decision"]
            )
        elif (
            known.get("known",False)
            and known.get("occurrences",0)>=3
            and known.get("label")=="FALSE_POSITIVE"
        ):
            decision["known_status"]="KNOWN_FALSE_POSITIVE"
            print(
                "[ALERT MEMORY] Known FALSE_POSITIVE detected "
                "but rule-based decision remains PRIORITY:",
                decision["decision"]
            )
        else:
            decision["known_status"]="NEW_ALERT"

        zero_day_result=(
            risk.get("zero_day",{})
            or {}
        )

        zero_day_score=zero_day_result.get("score",0)
        zero_day_suspected=zero_day_result.get(
            "suspected",
            False
        )

        allow_baseline_learning=should_update_baseline(
            zero_day_score,
            decision.get("decision"),
            zero_day_suspected,
            malicious_iocs=risk.get(
                "malicious_iocs",
                0
            )
        )

        behavior=build_behavior_fingerprint(
            normalized
        )

        baseline_update=update_baseline(
            normalized.get("hostname"),
            behavior,
            allow_learning=allow_baseline_learning
        )

        print(
            "[ZERO-DAY] Baseline learning:",
            baseline_update
        )

        ml_result=ml_predict(
            normalized,
            risk
        )

        ml_analysis=_build_ml_analysis(
            decision["decision"],
            ml_result,
            known_status=decision.get("known_status")
        )

        normalized["ml_analysis"]=ml_analysis

        response=build_response(
            decision["decision"],
            normalized,
            risk,
            ml_result
        )

        complete_report=generate_complete_report(
            normalized=normalized,
            risk=risk,
            decision=decision,
            ml_result=ml_result,
            ml_analysis=ml_analysis,
            known_alert=known,
            response=response
        )

        print("="*80)
        print("[REPORT] Complete report generated")
        print(
            "[REPORT] Incident ID :",
            complete_report.get("incident_id")
        )
        print(
            "[REPORT] Final decision :",
            complete_report.get("final_decision")
        )
        print("="*80)

        try:
            requests.post(
                f"{RESPONSE_ENGINE_URL}/report",
                json={
                    "incident_id":complete_report.get(
                        "incident_id"
                    ),
                    "report_html":complete_report.get("html")
                },
                timeout=10
            )
        except Exception as report_error:
            print(
                "[REPORT] Failed to deliver report_html:",
                report_error
            )

        db_result=save_incident(
            normalized,
            risk,
            decision,
            is_known_alert=known.get(
                "known",
                False
            ),
            ml_result=ml_result
        )

        fingerprint=build_fingerprint(normalized)

        should_notify,burst_count=(
            get_or_update_notification_throttle(
                fingerprint,
                window_seconds=300
            )
        )

        force_notify=(
            ml_analysis.get("severity")=="HIGH"
            or decision.get(
                "analyst_approval_required",
                False
            )
            or risk.get(
                "zero_day",
                {}
            ).get(
                "suspected",
                False
            )
        )

        if not should_notify and not force_notify:
            response["actions"]=[
                action
                for action in response.get("actions",[])
                if action.get("tool")!="notification"
            ]
        else:
            for action in response.get("actions",[]):
                if action.get("tool")=="notification":
                    context=action.setdefault(
                        "context",
                        {}
                    )

                    context["burst_count"]=burst_count

                    if force_notify and not should_notify:
                        context["throttle_override"]=(
                            "SECURITY_ENRICHMENT"
                        )

        response["throttled"]=(
            not should_notify
            and not force_notify
        )

        response["burst_count"]=burst_count

        return JSONResponse({
            "success":True,
            "risk":risk,
            "decision":decision,
            "ml":{
                "result":ml_result,
                "analysis":ml_analysis
            },
            "known_alert":known,
            "response":response,
            "report":{
                "generated":True,
                "incident_id":complete_report.get(
                    "incident_id"
                ),
                "final_score":complete_report.get(
                    "final_score"
                ),
                "final_decision":complete_report.get(
                    "final_decision"
                )
            },
            "db":db_result
        })

    except Exception as e:
        traceback.print_exc()

        return JSONResponse(
            status_code=500,
            content={
                "success":False,
                "error":str(e)
            }
        )

def get_incident_for_label(incident_id):
    conn=sqlite3.connect("/app/incidents.db")
    conn.row_factory=sqlite3.Row

    try:
        row=conn.execute(
            """
            SELECT
                incident_id,
                hostname,
                incident_type,
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
                occurrence_count
            FROM incidents
            WHERE incident_id=?
            """,
            (str(incident_id),)
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()

@app.post("/label")
async def label(request:Request):
    try:
        payload=await request.json()

        incident_id=payload.get("incident_id")
        lbl=payload.get("label")

        normalized=(
            payload.get("normalized",{})
            or {}
        )

        if (
            not incident_id
            or lbl not in {
                "TRUE_POSITIVE",
                "FALSE_POSITIVE"
            }
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":(
                        "incident_id and "
                        "a valid label "
                        "are required."
                    )
                }
            )

        if not normalized:
            normalized=(
                get_incident_for_label(
                    incident_id
                )
                or {}
            )

        if not normalized:
            return JSONResponse(
                status_code=404,
                content={
                    "success":False,
                    "error":"Incident not found."
                }
            )

        label_result=update_label(
            incident_id,
            lbl,
            source="analyst"
        )

        memory_result=save_label(
            normalized,
            lbl
        )

        retrain_manager.maybe_retrain_async(
            triggered_by="analyst_label"
        )

        return JSONResponse({
            "success":True,
            "incident_id":incident_id,
            "label":lbl,
            "label_changed":label_result.get(
                "changed"
            ),
            "memory":memory_result,
            "ml_training":{
                "queued":True,
                "model_exists":os.path.exists(
                    MODEL_PATH
                )
            }
        })

    except Exception as e:
        traceback.print_exc()

        return JSONResponse(
            status_code=500,
            content={
                "success":False,
                "error":str(e)
            }
        )

@app.get("/label/{label}/{incident_id}")
async def label_from_email(
    label:str,
    incident_id:str
):
    try:
        if label not in {
            "TRUE_POSITIVE",
            "FALSE_POSITIVE"
        }:
            return HTMLResponse(
                content="""
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>SOC - Label Error</title>
                </head>
                <body style="
                    font-family:Arial,sans-serif;
                    background:#f4f6f8;
                    padding:40px;
                ">
                    <div style="
                        max-width:600px;
                        margin:auto;
                        background:white;
                        padding:30px;
                        border-radius:8px;
                    ">
                        <h2>❌ Label invalide</h2>
                        <p>
                            Le label fourni n'est pas valide.
                        </p>
                    </div>
                </body>
                </html>
                """,
                status_code=400
            )

        incident=get_incident_for_label(
            incident_id
        )

        if incident is None:
            safe_id=html.escape(str(incident_id))

            return HTMLResponse(
                content=f"""
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>SOC - Incident introuvable</title>
                </head>
                <body style="
                    font-family:Arial,sans-serif;
                    background:#f4f6f8;
                    padding:40px;
                ">
                    <div style="
                        max-width:600px;
                        margin:auto;
                        background:white;
                        padding:30px;
                        border-radius:8px;
                        box-shadow:0 2px 8px rgba(0,0,0,0.1);
                    ">
                        <h2>❌ Incident introuvable</h2>
                        <p>
                            Aucun incident correspondant à :
                        </p>
                        <p><b>{safe_id}</b></p>
                        <p style="color:#666;margin-top:20px;">
                            Vérifie que l'incident existe
                            toujours dans incidents.db.
                        </p>
                    </div>
                </body>
                </html>
                """,
                status_code=404
            )

        normalized={
            "incident_id":incident.get("incident_id"),
            "hostname":incident.get("hostname"),
            "incident_type":incident.get("incident_type"),
            "rule_id":incident.get("rule_id"),
            "description":incident.get("description"),
            "rule_level":incident.get("rule_level"),
            "classification_confidence":incident.get(
                "classification_confidence"
            ),
            "ioc_total":incident.get("ioc_total"),
            "ioc_hashes":incident.get("ioc_hashes"),
            "ioc_ips":incident.get("ioc_ips"),
            "ioc_domains":incident.get("ioc_domains"),
            "ioc_urls":incident.get("ioc_urls"),
            "decision_engine_score":incident.get(
                "decision_engine_score"
            ),
            "misp_score":incident.get("misp_score"),
            "cortex_score":incident.get("cortex_score"),
            "malicious_iocs":incident.get("malicious_iocs"),
            "occurrence_count":incident.get("occurrence_count")
        }

        update_label(
            incident_id,
            label,
            source="analyst"
        )

        memory_result=save_label(
            normalized,
            label
        )

        retrain_manager.maybe_retrain_async(
            triggered_by="analyst_label_email"
        )

        safe_id=html.escape(str(incident_id))
        safe_label=html.escape(str(label))

        label_text=(
            "TRUE POSITIVE"
            if label=="TRUE_POSITIVE"
            else "FALSE POSITIVE"
        )

        safe_label_text=html.escape(label_text)

        hostname=html.escape(
            str(
                incident.get("hostname")
                or "unknown"
            )
        )

        description=html.escape(
            str(
                incident.get("description")
                or ""
            )
        )

        return HTMLResponse(
            content=f"""
            <html>
            <head>
                <meta charset="UTF-8">
                <title>SOC - Analyst Label</title>
            </head>
            <body style="
                font-family:Arial,sans-serif;
                background:#f4f6f8;
                padding:40px;
            ">
                <div style="
                    max-width:650px;
                    margin:auto;
                    background:white;
                    padding:30px;
                    border-radius:8px;
                    box-shadow:0 2px 8px rgba(0,0,0,0.1);
                ">
                    <h2>Incident labellisé</h2>
                    <hr>
                    <p>
                        <b>Incident :</b>
                        {safe_id}
                    </p>
                    <p>
                        <b>Host :</b>
                        {hostname}
                    </p>
                    <p>
                        <b>Verdict analyste :</b>
                        {safe_label_text}
                    </p>
                    {
                        f'''
                        <p>
                            <b>Description :</b>
                            {description}
                        </p>
                        '''
                        if description
                        else ""
                    }
                    <p style="color:#666;margin-top:20px;">
                        Le label a été enregistré
                        dans le système SOC.
                    </p>
                    <p style="color:#666;">
                        Il pourra être utilisé
                        pour la mémoire comportementale
                        et le réentraînement ML automatique.
                    </p>
                    <p style="color:#666;">
                        ML model status :
                        {
                            "Disponible"
                            if os.path.exists(MODEL_PATH)
                            else "En attente de données suffisantes"
                        }
                    </p>
                </div>
            </body>
            </html>
            """,
            status_code=200
        )

    except Exception as e:
        traceback.print_exc()

        safe_error=html.escape(str(e))

        return HTMLResponse(
            content=f"""
            <html>
            <head>
                <meta charset="UTF-8">
                <title>SOC - Error</title>
            </head>
            <body style="
                font-family:Arial,sans-serif;
                background:#f4f6f8;
                padding:40px;
            ">
                <div style="
                    max-width:650px;
                    margin:auto;
                    background:white;
                    padding:30px;
                    border-radius:8px;
                ">
                    <h2>Erreur lors du labeling</h2>
                    <p>{safe_error}</p>
                </div>
            </body>
            </html>
            """,
            status_code=500
        )

@app.get("/ml/status")
async def ml_status():
    try:
        probe=ml_predict({},{})

        return calculate_ml_status(probe)

    except Exception as e:
        traceback.print_exc()

        return JSONResponse(
            status_code=500,
            content={
                "success":False,
                "error":str(e)
            }
        )

@app.get("/ml/agreement")
async def ml_agreement(window_hours:int=24):
    try:
        return analyze_ml_rule_agreement(
            window_hours
        )

    except Exception as e:
        traceback.print_exc()

        return JSONResponse(
            status_code=500,
            content={
                "success":False,
                "error":str(e)
            }
        )