from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse,HTMLResponse
from weasyprint import HTML
import traceback
import json
import os
import requests
from mailer import send_email
from executor import execute_actions
from pending_action import get_pending,consume_pending
from velociraptor import run_velociraptor_action
from pydantic import BaseModel
from typing import Any,Dict,List
from report_store import save_report_html

app=FastAPI(
    title="Response Engine",
    version="1.1.0"
)

FINAL_DECISION_URL=os.getenv(
    "FINAL_DECISION_URL",
    "http://final-decision:8090"
)

RESPONSE_ENGINE_PUBLIC_URL=os.getenv(
    "RESPONSE_ENGINE_PUBLIC_URL",
    "http://localhost:8095"
)

REPORT_DIR=os.getenv(
    "REPORT_DIR",
    "/tmp/soc_reports"
)

os.makedirs(REPORT_DIR,exist_ok=True)

@app.get("/")
async def root():
    return {
        "service":"Response Engine",
        "status":"running"
    }

@app.get("/health")
async def health():
    return {
        "status":"healthy"
    }

class ExecuteRequest(BaseModel):
    actions:List[Dict[str,Any]]=[]

@app.post("/execute")
async def execute(request:Request):
    try:
        raw_body=await request.body()
        raw_text=raw_body.decode("utf-8",errors="replace").strip()

        print("="*80)
        print("CONTENT-TYPE :",request.headers.get("content-type"))
        print("RAW BODY RECU :")
        print(raw_text)
        print("="*80)

        if not raw_text:
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":"Empty request body received from Shuffle."
                }
            )

        try:
            payload=json.loads(raw_text)
        except json.JSONDecodeError as e:
            print("JSON PARSING ERROR :",str(e))
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":"Invalid JSON received from Shuffle.",
                    "parse_error":str(e),
                    "raw_body":raw_text[:2000]
                }
            )

        print("="*80)
        print("PAYLOAD RECU DU FINAL DECISION / SHUFFLE :")
        print(json.dumps(payload,indent=2))
        print("="*80)

        if not isinstance(payload,dict):
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":"Payload must be a JSON object."
                }
            )

        response=payload.get("response")

        if response is None:
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":"Missing 'response' field.",
                    "received_keys":list(payload.keys())
                }
            )

        if not isinstance(response,dict):
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":"'response' must be a JSON object."
                }
            )

        automatic=bool(response.get("automatic",False))
        actions=response.get("actions",[])

        if not isinstance(actions,list):
            actions=[]

        print("AUTOMATIC :",automatic)
        print("NUMBER OF ACTIONS :",len(actions))
        print("ACTIONS :")
        print(json.dumps(actions,indent=2))

        if not actions:
            print(">>> NO ACTIONS TO EXECUTE")
            return JSONResponse({
                "success":True,
                "executed":False,
                "automatic":automatic,
                "message":"No actions to execute.",
                "results":[]
            })

        print(f">>> EXECUTING {len(actions)} ACTION(S)")
        results=execute_actions(actions)

        print("EXECUTION RESULTS :")
        print(json.dumps(results,indent=2))

        return JSONResponse({
            "success":True,
            "executed":True,
            "automatic":automatic,
            "actions":len(actions),
            "results":results
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

@app.get(
    "/label/{label}/{incident_id}",
    response_class=HTMLResponse
)
async def label_incident(label:str,incident_id:str):
    print("="*80)
    print("ANALYST LABEL REQUEST")
    print("INCIDENT ID :",incident_id)
    print("LABEL :",label)
    print("FINAL DECISION URL :",FINAL_DECISION_URL)
    print("="*80)

    if label not in ("TRUE_POSITIVE","FALSE_POSITIVE"):
        return HTMLResponse(
            """
            <html>
            <body style="font-family:Arial,sans-serif;">
                <h2>❌ Invalid label</h2>
                <p>The selected analyst label is not valid.</p>
            </body>
            </html>
            """,
            status_code=400
        )

    try:
        payload={
            "incident_id":incident_id,
            "label":label,
            "normalized":{}
        }

        final_decision_endpoint=f"{FINAL_DECISION_URL.rstrip('/')}/label"

        print(">>> POST FINAL DECISION :",final_decision_endpoint)
        print(">>> PAYLOAD :",json.dumps(payload,indent=2))

        response=requests.post(
            final_decision_endpoint,
            json=payload,
            timeout=10
        )

        print("FINAL DECISION STATUS :",response.status_code)
        print("FINAL DECISION RESPONSE :",response.text)

        if response.status_code!=200:
            return HTMLResponse(
                f"""
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
                        max-width:650px;
                        margin:auto;
                        background:white;
                        padding:30px;
                        border-radius:8px;
                        box-shadow:0 2px 8px rgba(0,0,0,0.1);
                    ">
                        <h2>❌ Échec de la labellisation</h2>
                        <hr>
                        <p><b>Incident :</b> {incident_id}</p>
                        <p><b>Label :</b> {label}</p>
                        <p><b>HTTP Final Decision :</b> {response.status_code}</p>
                        <p><b>Réponse :</b> {response.text}</p>
                    </div>
                </body>
                </html>
                """,
                status_code=500
            )

        return HTMLResponse(
            f"""
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
                    <h2>✅ Incident labellisé</h2>
                    <hr>
                    <p><b>Incident :</b> {incident_id}</p>
                    <p><b>Verdict analyste :</b> {label}</p>
                    <p style="color:#666;margin-top:20px;">
                        Le label a été enregistré dans le système SOC.
                    </p>
                    <p style="color:#666;">
                        Il pourra être utilisé pour la mémoire comportementale
                        et le futur réentraînement ML.
                    </p>
                </div>
            </body>
            </html>
            """
        )

    except requests.exceptions.RequestException as e:
        traceback.print_exc()
        return HTMLResponse(
            f"""
            <html>
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
                    <h2>❌ Final Decision inaccessible</h2>
                    <p>Impossible de contacter le Final Decision Engine.</p>
                    <p><b>URL :</b> {FINAL_DECISION_URL}</p>
                    <p><b>Erreur :</b> {str(e)}</p>
                </div>
            </body>
            </html>
            """,
            status_code=502
        )

    except Exception as e:
        traceback.print_exc()
        return HTMLResponse(
            f"""
            <html>
            <body style="font-family:Arial,sans-serif;">
                <h2>❌ Labeling error</h2>
                <p>{str(e)}</p>
            </body>
            </html>
            """,
            status_code=500
        )

@app.get(
    "/approve/{token}",
    response_class=HTMLResponse
)
async def approve(token:str):
    print("="*80)
    print("APPROVAL REQUEST")
    print("TOKEN :",token)
    print("="*80)

    action=get_pending(token)

    if action is None:
        return HTMLResponse(
            """
            <html>
            <body style="font-family:Arial,sans-serif;">
                <h2>Invalid or expired approval link</h2>
                <p>
                    This approval link is invalid,
                    expired, or has already been used.
                </p>
            </body>
            </html>
            """,
            status_code=410
        )

    print(">>> ANALYST APPROVED ACTION")
    print(json.dumps(action,indent=2))

    result=run_velociraptor_action(action)

    print("="*80)
    print("VELOCIRAPTOR RESULT:")
    print(json.dumps(result,indent=2))
    print("="*80)

    if result.get("success"):
        consume_pending(token)

        return HTMLResponse(
            f"""
            <html>
            <body style="font-family:Arial,sans-serif;">
                <h2>✅ Action launched successfully</h2>
                <p>Artifact: <b>{result.get('artifact')}</b></p>
                <p>Host: <b>{result.get('hostname')}</b></p>
                <p>Flow ID: <b>{result.get('flow_id')}</b></p>
                <p>
                    The Velociraptor flow has been
                    started successfully.
                </p>
            </body>
            </html>
            """
        )

    return HTMLResponse(
        f"""
        <html>
        <body style="font-family:Arial,sans-serif;">
            <h2>❌ Action failed</h2>
            <p>{result.get('message','Unknown error')}</p>
        </body>
        </html>
        """,
        status_code=500
    )

@app.post("/report")
async def receive_report(request:Request):
    try:
        payload=await request.json()
        incident_id=payload.get("incident_id")
        report_html=payload.get("report_html")

        if not incident_id or not report_html:
            return JSONResponse(
                status_code=400,
                content={
                    "success":False,
                    "error":"Missing incident_id or report_html."
                }
            )

        save_report_html(incident_id,report_html)

        return JSONResponse({
            "success":True,
            "stored":True,
            "incident_id":incident_id
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