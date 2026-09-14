import html
import re
from datetime import datetime
import json
import markdown

def _safe(value):
    if value is None:
        return ""
    return html.escape(str(value))

def _pretty_json(value):
    try:
        return html.escape(json.dumps(value,ensure_ascii=False,indent=2,default=str))
    except Exception:
        return _safe(value)

def _join_if_list(value):
    if isinstance(value,list):
        return ", ".join(str(v) for v in value if v is not None)
    return value

def _format_list(items):
    if not items:
        return "<p>Aucune donnée</p>"
    if not isinstance(items,list):
        items=[items]
    rows=[]
    for item in items:
        if isinstance(item,dict):
            value=_safe(item.get("value","unknown"))
            score=item.get("score")
            reason=item.get("reason")
            source=item.get("source")
            details=[]
            if score is not None:
                details.append(f"Score : {_safe(score)}")
            if reason:
                details.append(f"Raison : {_safe(reason)}")
            if source:
                details.append(f"Source : {_safe(source)}")
            extra="<br>"+" | ".join(details) if details else ""
            rows.append(f"<tr><td>{value}{extra}</td></tr>")
        else:
            rows.append(f"<tr><td>{_safe(item)}</td></tr>")
    return f"""
    <table>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """

def _section(title,content):
    return f"""
    <div class="section">
        <h2>{_safe(title)}</h2>
        {content}
    </div>
    """

def _key_value_table(data):
    rows=[]
    for key,value in data.items():
        if isinstance(value,(dict,list)):
            if isinstance(value,dict):
                value_html="<pre>"+_pretty_json(value)+"</pre>"
            else:
                value_html="<pre>"+_safe(str(value))+"</pre>"
        else:
            value_html=_safe(value)
        rows.append(
            f"""
            <tr>
                <td><b>{_safe(key)}</b></td>
                <td>{value_html}</td>
            </tr>
            """
        )
    return f"""
    <table>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """

KEEP_INVESTIGATION_SECTIONS=["4","5","6"]

def _filter_investigation_sections(markdown_text,keep_numbers=None):
    if not markdown_text:
        return markdown_text
    if keep_numbers is None:
        keep_numbers=KEEP_INVESTIGATION_SECTIONS
    parts=re.split(r'(?m)^(## .+)$',markdown_text)
    output=[parts[0]]
    for i in range(1,len(parts),2):
        heading=parts[i]
        body=parts[i+1] if i+1<len(parts) else ""
        if any(heading.strip().startswith(f"## {n}.") for n in keep_numbers):
            output.append(heading)
            output.append(body)
    return "".join(output)

def generate_complete_report(
    normalized,
    risk,
    decision,
    ml_result,
    ml_analysis,
    known_alert=None,
    response=None
):
    normalized=normalized or {}
    risk=risk or {}
    decision=decision or {}
    ml_result=ml_result or {}
    ml_analysis=ml_analysis or {}
    known_alert=known_alert or {}
    response=response or {}
    investigation_report=normalized.get("investigation_report","")

    if investigation_report:
        print(f"[REPORT] Investigation report received ({len(investigation_report)} characters)")
        filtered_report=_filter_investigation_sections(
            investigation_report,
            KEEP_INVESTIGATION_SECTIONS
        )
        investigation_report_html=markdown.markdown(
            filtered_report,
            extensions=["tables","fenced_code"]
        )
    else:
        print("[REPORT] No investigation report received")
        investigation_report_html="<p><em>Rapport d'investigation non disponible.</em></p>"

    generated_at=datetime.utcnow().isoformat()
    incident_id=normalized.get("incident_id","unknown")
    hostname=normalized.get("hostname","unknown")
    incident_type=normalized.get("incident_type","unknown")
    description=normalized.get("description","")
    final_score=risk.get("final_score",0)
    final_decision=decision.get("decision","UNKNOWN")
    risk_level=decision.get("risk_level",decision.get("risk","UNKNOWN"))

    ioc_summary=normalized.get("ioc_summary",{}) or {}
    ioc_ips=ioc_summary.get("ips",[])
    ioc_domains=ioc_summary.get("domains",[])
    ioc_urls=ioc_summary.get("urls",[])
    ioc_hashes=ioc_summary.get("hashes",[])

    ioc_stats=normalized.get("ioc_statistics",{}) or {}
    ioc_total=ioc_stats.get("total",0)
    malicious_iocs=risk.get("malicious_iocs",0)

    classification_data=normalized.get("classification",{}) or {}
    classification_confidence=normalized.get("classification_confidence")

    if classification_confidence is None:
        classification_confidence=classification_data.get("confidence")

    mitre_data=normalized.get("mitre",{}) or {}
    mitre_tactic=normalized.get("mitre_tactic")

    if mitre_tactic is None and isinstance(mitre_data,dict):
        mitre_tactic=mitre_data.get("tactic")

    mitre_tactic=_join_if_list(mitre_tactic)
    mitre_technique=normalized.get("mitre_technique")

    if mitre_technique is None and isinstance(mitre_data,dict):
        mitre_technique=mitre_data.get(
            "technique_name",
            mitre_data.get("technique")
        )

    mitre_technique=_join_if_list(mitre_technique)

    decision_engine_data=risk.get("decision_engine",{}) or {}
    decision_engine_score=decision_engine_data.get(
        "score",
        risk.get(
            "decision_engine_score",
            normalized.get("decision_engine_score",0)
        )
    )

    misp_data=risk.get("misp",{}) or risk.get("misp_results",{}) or {}
    misp_score=misp_data.get(
        "score",
        risk.get(
            "misp_score",
            normalized.get("misp_score",0)
        )
    )

    cortex_data=risk.get("cortex",{}) or risk.get("cortex_results",{}) or {}
    cortex_score=cortex_data.get(
        "score",
        risk.get(
            "cortex_score",
            normalized.get("cortex_score",0)
        )
    )

    zero_day=risk.get("zero_day",{}) or {}
    zero_day_score=zero_day.get("score",0)
    zero_day_risk=zero_day.get("risk","UNKNOWN")
    zero_day_confidence=zero_day.get("confidence",0)
    zero_day_suspected=zero_day.get("suspected",False)
    zero_day_indicators=zero_day.get("indicators",[])
    zero_day_reasons=zero_day.get("reasons",[])

    ml_available=ml_result.get("available",False)
    ml_prediction=ml_result.get("prediction","UNAVAILABLE")
    ml_confidence=ml_result.get("confidence",0)
    ml_confidence_level=ml_result.get("confidence_level","UNKNOWN")
    ml_probability=ml_result.get(
        "probability_true_positive",
        ml_result.get("proba_true_positive",0)
    )
    ml_model_version=ml_result.get("model_version","unknown")
    ml_disagreement=ml_analysis.get("disagreement",False)
    ml_disagreement_severity=ml_analysis.get("severity","NONE")
    ml_learning_priority=ml_analysis.get("learning_priority",0)
    response_actions=response.get("actions",[])

    investigation_report_section=f"""
    <div class="section">
        <h2>3. Rapport d'investigation — Decision Engine</h2>
        <div class="investigation-report">
            {investigation_report_html}
        </div>
    </div>
    """

    general_section=_section(
        "1. Informations générales",
        _key_value_table(
            {
                "Incident ID":incident_id,
                "Hostname":hostname,
                "Type d'incident":incident_type,
                "Description":description,
                "IOC total":ioc_total,
                "IOC malveillants confirmés":malicious_iocs,
                "Rapport généré":generated_at
            }
        )
    )

    decision_engine_section=_section(
        "2. Analyse du Decision Engine",
        _key_value_table(
            {
                "Rule ID":normalized.get("rule_id"),
                "Rule level":normalized.get("rule_level"),
                "Classification confidence":classification_confidence,
                "Incident type":incident_type,
                "MITRE tactic":mitre_tactic,
                "MITRE technique":mitre_technique
            }
        )
    )

    ioc_section=_section(
        "7. Indicateurs de compromission",
        f"""
        <h3>IPs</h3>
        {_format_list(ioc_ips)}
        <h3>Domaines</h3>
        {_format_list(ioc_domains)}
        <h3>URLs</h3>
        {_format_list(ioc_urls)}
        <h3>Hashes</h3>
        {_format_list(ioc_hashes)}
        """
    )

    misp_section=_section(
        "8. Analyse MISP",
        f"""
        {_key_value_table(
            {
                "Score MISP":misp_score,
                "IOC malveillants":malicious_iocs
            }
        )}
        <h3>Résultats MISP</h3>
        <pre>{_pretty_json(misp_data)}</pre>
        """
    )

    cortex_section=_section(
        "9. Analyse Cortex",
        f"""
        {_key_value_table({"Score Cortex":cortex_score})}
        <h3>Résultats des analyseurs</h3>
        <pre>{_pretty_json(cortex_data)}</pre>
        """
    )

    zero_day_section=_section(
        "10. Analyse Zero-Day / comportementale",
        _key_value_table(
            {
                "Zero-Day score":zero_day_score,
                "Zero-Day risk":zero_day_risk,
                "Zero-Day confidence":zero_day_confidence,
                "Suspicion Zero-Day":zero_day_suspected,
                "Indicators":zero_day_indicators,
                "Reasons":zero_day_reasons
            }
        )
    )

    scoring_section=_section(
        "11. Scoring final",
        f"""
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Decision Engine</td>
                    <td>{_safe(decision_engine_score)}</td>
                </tr>
                <tr>
                    <td>MISP</td>
                    <td>{_safe(misp_score)}</td>
                </tr>
                <tr>
                    <td>Cortex</td>
                    <td>{_safe(cortex_score)}</td>
                </tr>
                <tr>
                    <td>Zero-Day</td>
                    <td>{_safe(zero_day_score)}</td>
                </tr>
                <tr>
                    <td><b>Final Score</b></td>
                    <td><b>{_safe(final_score)}/100</b></td>
                </tr>
            </tbody>
        </table>
        """
    )

    final_decision_section=_section(
        "12. Décision finale",
        f"""
        <div class="decision">
            <p><b>Décision :</b> {_safe(final_decision)}</p>
            <p><b>Niveau de risque :</b> {_safe(risk_level)}</p>
            <p><b>Réponse requise :</b> {_safe(decision.get("response_required",False))}</p>
            <p><b>Validation analyste requise :</b> {_safe(decision.get("analyst_approval_required",False))}</p>
            <p><b>Known alert :</b> {_safe(known_alert.get("known",False))}</p>
            <p><b>Known label :</b> {_safe(known_alert.get("label"))}</p>
            <p><b>Known occurrences :</b> {_safe(known_alert.get("occurrences",0))}</p>
        </div>
        """
    )

    ml_section=_section(
        "13. Analyse Machine Learning",
        _key_value_table(
            {
                "ML disponible":ml_available,
                "Prediction":ml_prediction,
                "TRUE_POSITIVE probability":ml_probability,
                "Confidence":ml_confidence,
                "Confidence level":ml_confidence_level,
                "Model version":ml_model_version,
                "Rule / ML disagreement":ml_disagreement,
                "Disagreement severity":ml_disagreement_severity,
                "Learning priority":ml_learning_priority
            }
        )
    )

    response_section=_section(
        "14. Réponse proposée",
        f"<pre>{_pretty_json(response_actions)}</pre>"
    )

    report_html=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>SOC Incident Report - {_safe(incident_id)}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f6f8;
                margin: 0;
                padding: 30px;
                color: #222;
            }}
            .container {{
                max-width: 950px;
                margin: auto;
                background: white;
                padding: 30px;
                border-radius: 10px;
            }}
            h1 {{
                margin-top: 0;
            }}
            h2 {{
                border-bottom: 1px solid #ddd;
                padding-bottom: 8px;
            }}
            h3 {{
                margin-top: 20px;
            }}
            .header {{
                padding: 20px;
                background: #eef2f7;
                border-left: 5px solid #34495e;
                margin-bottom: 25px;
            }}
            .decision {{
                padding: 18px;
                background: #fff3cd;
                border-left: 5px solid #f39c12;
            }}
            .section {{
                margin-top: 25px;
            }}
            table {{
                width: 100%;
                max-width: 100%;
                table-layout: auto;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th,td {{
                border: 1px solid #ddd;
                padding: 9px;
                text-align: left;
                vertical-align: top;
                word-break: break-word;
                overflow-wrap: anywhere;
                max-width: 0;
            }}
            th {{
                background: #f4f4f4;
            }}
            pre {{
                background: #f5f5f5;
                padding: 12px;
                border-radius: 5px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-word;
                overflow-wrap: anywhere;
            }}
            code {{
                word-break: break-all;
                overflow-wrap: anywhere;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SOC Incident Report</h1>
            <div class="header">
                <p><b>Incident ID :</b> {_safe(incident_id)}</p>
                <p><b>Host :</b> {_safe(hostname)}</p>
                <p><b>Incident :</b> {_safe(incident_type)}</p>
                <p><b>Final Score :</b> {_safe(final_score)}/100</p>
                <p><b>Final Decision :</b> {_safe(final_decision)}</p>
            </div>
            {general_section}
            {decision_engine_section}
            {investigation_report_section}
            {ioc_section}
            {misp_section}
            {cortex_section}
            {zero_day_section}
            {scoring_section}
            {final_decision_section}
            {ml_section}
            {response_section}
        </div>
    </body>
    </html>
    """

    return {
        "incident_id":incident_id,
        "hostname":hostname,
        "incident_type":incident_type,
        "final_score":final_score,
        "final_decision":final_decision,
        "risk_level":risk_level,
        "generated_at":generated_at,
        "html":report_html
    }