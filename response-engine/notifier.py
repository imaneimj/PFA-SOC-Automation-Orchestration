import os
import logging
from datetime import datetime
from mailer import send_email
from pending_action import create_pending
from weasyprint import HTML

logger=logging.getLogger("ResponseEngine")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s - %(message)s"
    )

RESPONSE_ENGINE_PUBLIC_URL=os.getenv(
    "RESPONSE_ENGINE_PUBLIC_URL",
    "http://localhost:8095"
).rstrip("/")

REPORT_DIR=os.getenv(
    "REPORT_DIR",
    "/tmp/soc_reports"
)

os.makedirs(REPORT_DIR,exist_ok=True)

TEMPLATES={
    "critical_alert":{
        "subject":"SOC ALERT - Critical Incident",
        "message":"A critical incident has been detected. Please review it immediately."
    },
    "monitor":{
        "subject":"SOC ALERT - Monitoring",
        "message":"An incident has been detected and placed under monitoring."
    },
    "false_positive_candidate":{
        "subject":"SOC ALERT - Low Risk Incident",
        "message":"The decision engine classified this incident as low risk. Analyst validation is required for dataset labeling."
    },
    "known_true_positive":{
        "subject":"SOC ALERT - Known True Positive",
        "message":"This alert has already been validated by an analyst as TRUE POSITIVE. The previous analyst label is reused automatically."
    },
    "known_false_positive":{
        "subject":"SOC ALERT - Known False Positive",
        "message":"This alert has already been validated by an analyst as FALSE POSITIVE. The previous analyst label is reused automatically."
    },
    "response_approval":{
        "subject":"SOC ALERT - Approval Required (AUTO_RESPONSE)",
        "message":"This incident meets the criteria for an automatic response. Analyst approval is required before any containment action is launched."
    },
    "containment_approval":{
        "subject":"SOC ALERT - Approval Required (AUTO_CONTAIN)",
        "message":"This incident meets the criteria for automatic containment. Analyst approval is required before any containment action is launched."
    }
}

def _generate_report_pdf(report_html:str,incident_id:str)->str:
    if not report_html:
        raise ValueError("Cannot generate PDF: report_html is empty.")

    safe_incident_id=str(incident_id or "unknown").replace("/","_")
    filename=f"SOC_Incident_Report_{safe_incident_id}.pdf"
    pdf_path=os.path.join(REPORT_DIR,filename)

    logger.info("Generating SOC report PDF: %s",pdf_path)

    full_html=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{
                size:A4;
                margin:18mm 15mm 18mm 15mm;
            }}
            * {{
                box-sizing:border-box;
            }}
            body {{
                font-family:Arial,Helvetica,sans-serif;
                font-size:10pt;
                color:#222;
                line-height:1.45;
                word-wrap:break-word;
                overflow-wrap:anywhere;
            }}
            h1 {{
                font-size:20pt;
                margin-bottom:8px;
            }}
            h2 {{
                font-size:15pt;
                margin-top:20px;
                word-wrap:break-word;
            }}
            h3 {{
                font-size:12pt;
                margin-top:15px;
            }}
            table {{
                width:100%;
                max-width:100%;
                table-layout:fixed;
                border-collapse:collapse;
                margin:10px 0;
            }}
            th,td {{
                border:1px solid #cccccc;
                padding:6px;
                vertical-align:top;
                font-size:8.5pt;
                word-break:break-word;
                overflow-wrap:anywhere;
                hyphens:auto;
            }}
            th {{
                font-weight:bold;
                background:#f1f1f1;
            }}
            pre {{
                white-space:pre-wrap;
                word-wrap:break-word;
                word-break:break-word;
                overflow-wrap:anywhere;
                overflow-x:hidden;
                max-width:100%;
                background:#f5f5f5;
                padding:8px;
                border-radius:4px;
                font-size:8pt;
            }}
            code {{
                font-family:"DejaVu Sans Mono",monospace;
                word-break:break-all;
                overflow-wrap:anywhere;
            }}
            ul {{
                margin-top:5px;
                padding-left:20px;
            }}
            li {{
                word-break:break-word;
                overflow-wrap:anywhere;
            }}
            img {{
                max-width:100%;
            }}
            .page-break {{
                page-break-before:always;
            }}
        </style>
    </head>
    <body>
        {report_html}
    </body>
    </html>
    """

    try:
        HTML(
            string=full_html,
            base_url=REPORT_DIR
        ).write_pdf(pdf_path)
    except Exception:
        logger.exception("Failed to generate PDF report.")
        raise

    if not os.path.exists(pdf_path):
        raise RuntimeError(
            "PDF generation finished but the file does not exist."
        )

    size=os.path.getsize(pdf_path)

    if size==0:
        raise RuntimeError("Generated PDF is empty.")

    logger.info("PDF generated successfully: %s bytes",size)

    return pdf_path

def generate_pdf_from_html(report_html:str,incident_id:str):
    pdf_path=_generate_report_pdf(report_html,incident_id)
    pdf_filename=os.path.basename(pdf_path)
    return pdf_path,pdf_filename

def _normalize_ioc_list(items):
    normalized=[]

    if not items:
        return normalized

    for i in items:
        if isinstance(i,dict):
            normalized.append({
                "value":i.get("value","unknown"),
                "score":i.get("score"),
                "reason":i.get("reason"),
                "source":i.get("source")
            })
        else:
            normalized.append({
                "value":str(i),
                "score":None,
                "reason":None,
                "source":None
            })

    return normalized

def _format_ioc_list(items,label):
    normalized=_normalize_ioc_list(items)

    if not normalized:
        return ""

    lines=[]

    for ioc in normalized[:10]:
        detail=ioc["value"]
        extras=[]

        if ioc["score"] is not None:
            extras.append(f"score {ioc['score']}")

        if ioc["reason"]:
            extras.append(ioc["reason"])

        if ioc["source"]:
            extras.append(f"source: {ioc['source']}")

        if extras:
            detail+=(
                " <span style='color:#888;'>"
                f"({', '.join(extras)})"
                "</span>"
            )

        lines.append(f"<li>{detail}</li>")

    return f"""
    <p style="margin:4px 0;">
        <b>{label} :</b>
    </p>
    <ul style="margin:0 0 8px 0;">
        {''.join(lines)}
    </ul>
    """

def _build_ml_block(context:dict)->str:
    if not context.get("ml_available"):
        return ""

    confidence=context.get("ml_confidence") or 0
    confidence_pct=round(confidence*100)

    proba_tp_pct=round(
        (context.get("ml_proba_true_positive") or 0)*100
    )

    prediction=context.get("ml_prediction")
    confidence_level=context.get("ml_confidence_level","UNKNOWN")
    disagreement=context.get("ml_disagreement",False)
    disagreement_severity=context.get(
        "ml_disagreement_severity",
        "NONE"
    )
    model_version=context.get("ml_model_version","unknown")

    if confidence_level=="HIGH":
        confidence_text="HIGH CONFIDENCE"
    elif confidence_level=="MEDIUM":
        confidence_text="MEDIUM CONFIDENCE"
    else:
        confidence_text="LOW CONFIDENCE"

    disagreement_note=""

    if disagreement:
        disagreement_note=f"""
        <div style="
            margin-top:10px;
            padding:10px;
            background:#fff3cd;
            border-left:4px solid #f39c12;
        ">
            <b>⚠ ML / Rule disagreement</b>
            <p style="margin:5px 0;">
                Le modèle ML et le moteur de règles produisent des verdicts différents.
            </p>
            <p style="margin:5px 0;">
                <b>Priorité :</b> {disagreement_severity}
            </p>
            <p style="margin:5px 0;">
                Une validation analyste est recommandée.
            </p>
        </div>
        """

    return f"""
    <div style="
        background:#eef2f7;
        border-left:4px solid #34495e;
        padding:12px 16px;
        margin:14px 0;
    ">
        <p style="margin:4px 0;"><b>ML Risk Advisor</b></p>
        <p style="margin:4px 0;">
            <b>Prediction :</b> {prediction}
        </p>
        <p style="margin:4px 0;">
            <b>TRUE_POSITIVE probability :</b> {proba_tp_pct}%
        </p>
        <p style="margin:4px 0;">
            <b>Confidence :</b> {confidence_pct}% ({confidence_text})
        </p>
        <p style="margin:4px 0;">
            <b>Model version :</b> {model_version}
        </p>
        {disagreement_note}
    </div>
    """

def _build_context_html(context:dict)->str:
    if not context:
        return ""

    hostname=context.get("hostname","unknown")
    incident_type=context.get("incident_type","unknown")
    score=context.get("final_score",0)
    malicious_iocs=context.get("malicious_iocs",0)
    rule_id=context.get("rule_id")
    rule_level=context.get("rule_level")
    description=context.get("description")
    confidence=context.get("confidence")
    mitre=context.get("mitre")
    agent_ip=context.get("agent_ip")
    incident_id=context.get("incident_id")
    timestamp=context.get("timestamp")
    label=context.get("label")

    if isinstance(mitre,dict):
        mitre_tactic=context.get("mitre_tactic") or mitre.get("tactic")
        mitre_technique=context.get("mitre_technique") or mitre.get("technique")
    else:
        mitre_tactic=context.get("mitre_tactic")
        mitre_technique=context.get("mitre_technique")

    meta_rows=""

    if incident_id:
        meta_rows+=f"""
        <p style="margin:4px 0;">
            <b>ID incident :</b> {incident_id}
        </p>
        """

    if timestamp:
        meta_rows+=f"""
        <p style="margin:4px 0;">
            <b>Horodatage :</b> {timestamp}
        </p>
        """

    if description:
        meta_rows+=f"""
        <p style="margin:4px 0;">
            <b>Description :</b> {description}
        </p>
        """

    if rule_id or rule_level:
        meta_rows+=f"""
        <p style="margin:4px 0;">
            <b>Règle :</b>
            {rule_id or '?'}
            (niveau {rule_level if rule_level is not None else '?'})
        </p>
        """

    if mitre_tactic or mitre_technique:
        tactic_str=", ".join(mitre_tactic) if isinstance(mitre_tactic,list) else mitre_tactic
        technique_str=", ".join(mitre_technique) if isinstance(mitre_technique,list) else mitre_technique

        meta_rows+=f"""
        <p style="margin:4px 0;">
            <b>MITRE :</b>
            {tactic_str or '?'} / {technique_str or '?'}
        </p>
        """

    if confidence is not None:
        try:
            confidence_value=round(float(confidence)*100)
            meta_rows+=f"""
            <p style="margin:4px 0;">
                <b>Confiance classification :</b> {confidence_value}%
            </p>
            """
        except (TypeError,ValueError):
            pass

    if agent_ip:
        meta_rows+=f"""
        <p style="margin:4px 0;">
            <b>IP agent :</b> {agent_ip}
        </p>
        """

    if label in ("TRUE_POSITIVE","FALSE_POSITIVE"):
        meta_rows+=f"""
        <p style="
            margin:8px 0;
            font-weight:bold;
        ">
            <b>Label analyste :</b> {label}
        </p>
        """

    burst_count=context.get("burst_count")
    burst_note=""

    if burst_count and burst_count>1:
        burst_note=f"""
        <p style="
            margin:8px 0;
            color:#c0392b;
            font-weight:bold;
        ">
            ⚠ Cette alerte s'est répétée {burst_count} fois récemment.
        </p>
        """

    ml_block=_build_ml_block(context)

    return f"""
    <div style="
        background:#f4f4f4;
        border-left:4px solid #c0392b;
        padding:12px 16px;
        margin:16px 0;
    ">
        <p style="margin:4px 0;"><b>Host :</b> {hostname}</p>
        <p style="margin:4px 0;"><b>Type d'incident :</b> {incident_type}</p>
        <p style="margin:4px 0;"><b>Score de risque :</b> {score}/100</p>
        <p style="margin:4px 0;">
            <b>IOC confirmés malveillants :</b> {malicious_iocs}
        </p>
        {burst_note}
        {meta_rows}
        {ml_block}
        {_format_ioc_list(context.get("ips"),"IP")}
        {_format_ioc_list(context.get("urls"),"URL")}
        {_format_ioc_list(context.get("domains"),"Domaines")}
        {_format_ioc_list(context.get("hashes"),"Hashes")}
    </div>
    """

def _build_label_buttons(incident_id:str,label=None)->str:
    if not incident_id:
        return ""

    if label is not None:
        label=str(label).strip().upper()

    if label in ("TRUE_POSITIVE","FALSE_POSITIVE"):
        logger.info(
            "Incident %s already labeled as %s. Label buttons will not be displayed.",
            incident_id,
            label
        )
        return ""

    true_positive_url=(
        f"{RESPONSE_ENGINE_PUBLIC_URL}/label/TRUE_POSITIVE/{incident_id}"
    )

    false_positive_url=(
        f"{RESPONSE_ENGINE_PUBLIC_URL}/label/FALSE_POSITIVE/{incident_id}"
    )

    return f"""
    <div style="
        margin:20px 0;
        padding:15px;
        background:#f8f9fa;
        border-radius:6px;
    ">
        <p style="
            margin:0 0 12px 0;
            font-weight:bold;
        ">
            Analyst verdict :
        </p>
        <a href="{true_positive_url}"
           style="
             background-color:#27ae60;
             color:#ffffff;
             padding:12px 20px;
             text-decoration:none;
             border-radius:4px;
             display:inline-block;
             font-weight:bold;
             margin-right:8px;
           ">
            TRUE POSITIVE
        </a>
        <a href="{false_positive_url}"
           style="
             background-color:#7f8c8d;
             color:#ffffff;
             padding:12px 20px;
             text-decoration:none;
             border-radius:4px;
             display:inline-block;
             font-weight:bold;
           ">
            FALSE POSITIVE
        </a>
    </div>
    """

class NotificationEngine:
    def send(self,action:dict)->dict:
        notification_type=action.get("action","unknown")
        template=TEMPLATES.get(notification_type)
        context=action.get("context",{})

        if template is None:
            logger.warning(
                "Unknown notification type: %s",
                notification_type
            )
            return {
                "success":False,
                "notification":notification_type,
                "message":"Unknown notification."
            }

        incident_id=context.get("incident_id")
        label=context.get("label")

        show_label_buttons=notification_type in (
            "false_positive_candidate",
            "monitor",
            "critical_alert",
            "response_approval",
            "containment_approval"
        )

        label_buttons=(
            _build_label_buttons(incident_id,label)
            if show_label_buttons
            else ""
        )

        body=f"""
        <html>
        <body style="font-family:Arial,sans-serif;">
            <p>{template["message"]}</p>
            {_build_context_html(context)}
            {label_buttons}
        </body>
        </html>
        """

        try:
            send_email(
                subject=template["subject"],
                body=body,
                html=True
            )
        except Exception as e:
            return {
                "success":False,
                "notification":notification_type,
                "message":f"Email sending failed: {e}"
            }

        logger.info(
            "Analyst notified (%s).",
            notification_type
        )

        return {
            "success":True,
            "notification":notification_type,
            "timestamp":datetime.utcnow().isoformat(),
            "message":"Analyst notified by email."
        }

def send_notification(action:dict):
    return NotificationEngine().send(action)

def send_approval_email(action:dict)->dict:
    token=create_pending(action)

    approval_url=f"{RESPONSE_ENGINE_PUBLIC_URL}/approve/{token}"
    hostname=action.get("target","unknown host")

    response_type=(
        action.get("response")
        or action.get("artifact","unknown")
    )

    context=action.get("context",{})
    is_quarantine=response_type=="QUARANTINE"

    subject_prefix="QUARANTAINE - " if is_quarantine else ""

    subject=(
        f"SOC ALERT - {subject_prefix}"
        f"Action required on {hostname}"
    )

    parameters=action.get("parameters",{})
    target_ip=parameters.get("IP","")
    severity_note=""

    if is_quarantine:
        severity_note="""
        <p style="
            color:#c0392b;
            font-weight:bold;
        ">
            ⚠ Action de DERNIER RECOURS :
            isolement réseau complet de la machine.
            Ne sera lancée qu'après votre validation.
        </p>
        """

    label=context.get("label")

    body=f"""
    <html>
    <body style="font-family:Arial,sans-serif;">
        <h2>SOC Action Required</h2>
        <p>
            An incident requires a response action on host
            <b>{hostname}</b>.
        </p>
        <p>
            Proposed response:
            <b>{response_type}</b>
        </p>
        {
            f'<p>Target IP: <b>{target_ip}</b></p>'
            if target_ip
            else ''
        }
        {severity_note}
        {_build_context_html(context)}
        <p>
            Click the button below to launch this response artifact
            on Velociraptor:
        </p>
        <p style="margin-top:20px;">
            <a href="{approval_url}"
               style="
                background-color:#c0392b;
                color:#ffffff;
                padding:12px 22px;
                text-decoration:none;
                border-radius:4px;
                display:inline-block;
                font-weight:bold;
               ">
                Approve &amp; Launch
            </a>
        </p>
        {_build_label_buttons(context.get("incident_id"),label)}
        <p style="font-size:12px;color:#888888;">
            This link is valid for a limited time and can only be used once.
        </p>
    </body>
    </html>
    """

    try:
        send_email(
            subject=subject,
            body=body,
            html=True
        )
    except Exception as e:
        return {
            "success":False,
            "tool":"velociraptor",
            "message":f"Approval email failed: {e}"
        }

    logger.info(
        "Approval email sent for %s (%s).",
        hostname,
        response_type
    )

    return {
        "success":True,
        "tool":"velociraptor",
        "status":"PENDING_APPROVAL",
        "target":hostname,
        "response_type":response_type,
        "approval_token":token,
        "message":"Approval email sent. Waiting for analyst click."
    }

def send_combined_action_email(actions:list)->list:
    if not actions:
        return []

    velociraptor_action=next(
        (
            a for a in actions
            if a.get("tool")=="velociraptor"
        ),
        None
    )

    notification_action=next(
        (
            a for a in actions
            if a.get("tool")=="notification"
        ),
        None
    )

    context=(
        (
            velociraptor_action
            or notification_action
            or {}
        ).get("context",{})
    )

    incident_id=context.get("incident_id")
    hostname=context.get("hostname","unknown")
    label=context.get("label")

    if label is not None:
        label=str(label).strip().upper()

    from report_store import pop_report_html

    report_html=(
        context.get("report_html")
        or pop_report_html(incident_id)
    )

    approval_section=""
    token=None
    response_type=None

    if velociraptor_action:
        response_type=(
            velociraptor_action.get("response")
            or velociraptor_action.get("artifact","unknown")
        )

        is_quarantine=response_type=="QUARANTINE"
        subject_prefix="QUARANTAINE - " if is_quarantine else ""

        subject=(
            f"SOC ALERT - {subject_prefix}"
            f"Action required on {hostname}"
        )

        parameters=velociraptor_action.get("parameters",{})
        target_ip=parameters.get("IP","")

        intro=f"""
        <h2 style="margin-bottom:10px;">
            SOC Action Required
        </h2>
        <p>
            An incident requires a response action on host
            <b>{hostname}</b>.
        </p>
        <p>
            Proposed response:
            <b>{response_type}</b>
        </p>
        """

        if target_ip:
            intro+=f"""
            <p>
                Target IP:
                <b>{target_ip}</b>
            </p>
            """

        if is_quarantine:
            intro+="""
            <p style="
                color:#c0392b;
                font-weight:bold;
            ">
                ⚠ Action de DERNIER RECOURS :
                isolement réseau complet de la machine.
                Ne sera lancée qu'après votre validation.
            </p>
            """

        token=create_pending(velociraptor_action)
        approval_url=f"{RESPONSE_ENGINE_PUBLIC_URL}/approve/{token}"

        approval_section=f"""
        <div style="
            margin:20px 0;
            padding:15px;
            background:#fff5f5;
            border-left:4px solid #c0392b;
        ">
            <p><b>Response approval required</b></p>
            <p>
                Click the button below to launch this response artifact
                on Velociraptor.
            </p>
            <p style="margin-top:15px;">
                <a href="{approval_url}"
                   style="
                    background-color:#c0392b;
                    color:#ffffff;
                    padding:12px 22px;
                    text-decoration:none;
                    border-radius:4px;
                    display:inline-block;
                    font-weight:bold;
                   ">
                    Approve &amp; Launch
                </a>
            </p>
            <p style="font-size:12px;color:#888888;">
                This link is valid for a limited time and can only be used once.
            </p>
        </div>
        """
    else:
        notif_type=(
            notification_action.get("action","unknown")
            if notification_action
            else "unknown"
        )

        template=TEMPLATES.get(
            notif_type,
            {
                "subject":"SOC ALERT",
                "message":"An incident requires review."
            }
        )

        subject=template["subject"]

        intro=f"""
        <h2>SOC Alert</h2>
        <p>{template["message"]}</p>
        """

    pdf_path=None
    pdf_filename=None

    if report_html:
        try:
            pdf_path=_generate_report_pdf(
                report_html,
                incident_id
            )
            pdf_filename=os.path.basename(pdf_path)
        except Exception:
            logger.exception("Unable to generate SOC PDF.")
            pdf_path=None
    else:
        logger.warning(
            "No report_html found in action context for incident %s",
            incident_id
        )

    if pdf_path:
        pdf_note=f"""
        <div style="
            margin:20px 0;
            padding:12px 16px;
            background:#eef7ee;
            border-left:4px solid #27ae60;
        ">
            <p style="margin:4px 0;font-weight:bold;">
                📎 Rapport SOC complet
            </p>
            <p style="margin:4px 0;">
                Le rapport complet de l'incident est disponible en pièce jointe :
                <b>{pdf_filename}</b>
            </p>
        </div>
        """
    else:
        pdf_note="""
        <div style="
            margin:20px 0;
            padding:12px 16px;
            background:#fff3cd;
            border-left:4px solid #f39c12;
        ">
            <p style="margin:4px 0;font-weight:bold;">
                ⚠ Rapport PDF indisponible
            </p>
            <p>
                Le rapport complet n'a pas pu être généré automatiquement.
            </p>
        </div>
        """

    label_buttons=_build_label_buttons(
        incident_id,
        label
    )

    body=f"""
    <html>
    <body style="
        font-family:Arial,sans-serif;
        color:#222;
        max-width:800px;
    ">
        {intro}
        {_build_context_html(context)}
        {pdf_note}
        {approval_section}
        {label_buttons}
        <hr style="
            margin-top:25px;
            border:none;
            border-top:1px solid #ddd;
        ">
        <p style="font-size:12px;color:#888888;">
            Response Engine<br>
            Automated SOC Platform
        </p>
    </body>
    </html>
    """

    try:
        send_email(
            subject=subject,
            body=body,
            html=True,
            attachment_path=pdf_path,
            attachment_filename=pdf_filename
        )
    except Exception as e:
        logger.exception("Combined email sending failed.")

        error_result={
            "success":False,
            "message":f"Combined email sending failed: {e}"
        }

        return [error_result for _ in actions]

    logger.info(
        "Combined Action Required email sent for incident %s (%s). PDF=%s Label=%s",
        incident_id,
        hostname,
        bool(pdf_path),
        label or "NOT_LABELED"
    )

    results=[]

    for action in actions:
        if action.get("tool")=="velociraptor":
            results.append({
                "success":True,
                "tool":"velociraptor",
                "status":"PENDING_APPROVAL",
                "target":hostname,
                "response_type":(
                    action.get("response")
                    or action.get("artifact")
                ),
                "approval_token":token,
                "report_pdf":pdf_filename,
                "message":(
                    "Combined Action Required email sent with SOC PDF report. "
                    "Waiting for analyst approval."
                )
            })
        else:
            results.append({
                "success":True,
                "notification":action.get("action"),
                "timestamp":datetime.utcnow().isoformat(),
                "report_pdf":pdf_filename,
                "message":"Analyst notified by email with SOC PDF report."
            })

    return results