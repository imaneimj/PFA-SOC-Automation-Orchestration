from scoring.decision_engine_scoring import score_decision_engine
from scoring.misp_scoring import compute_misp_score
from scoring.cortex_scoring import compute_cortex_score
from zero_day.detector import detect_zero_day
from zero_day.behavioral_fingerprint import build_behavior_fingerprint
from zero_day.behavioral_baseline import analyze_behavior
from config import SOURCE_WEIGHTS

MAX_SCORE=100

def clamp(value,minimum=0,maximum=MAX_SCORE):
    return max(minimum,min(maximum,value))

def _safe_dict(value):
    return value if isinstance(value,dict) else {}

def _safe_list(value):
    return value if isinstance(value,list) else []

def _safe_bool(value):
    if isinstance(value,bool):
        return value
    if isinstance(value,str):
        return value.strip().lower() in {
            "true","1","yes","oui","detected","suspicious"
        }
    if isinstance(value,(int,float)):
        return value!=0
    return False

def _safe_number(value,default=0.0):
    try:
        return float(value)
    except (TypeError,ValueError):
        return default

def _merge_bool(*values):
    return any(_safe_bool(value) for value in values)

def _merge_score(*values):
    scores=[]
    for value in values:
        try:
            scores.append(float(value))
        except (TypeError,ValueError):
            continue
    if not scores:
        return 0
    return clamp(max(scores))

def _has_indicator(indicators,name):
    target=str(name or "").strip().lower()
    return any(
        str(indicator or "").strip().lower()==target
        for indicator in (indicators or [])
    )

def calculate_final_score(decision_engine,misp_results,cortex_results):
    decision_engine=_safe_dict(decision_engine)
    misp_results=_safe_list(misp_results)
    cortex_results=_safe_list(cortex_results)

    de_result=score_decision_engine(decision_engine)

    ioc=_safe_dict(decision_engine.get("ioc"))
    alert_ioc_values=set()

    for key in ("ips","domains","urls","hashes"):
        values=ioc.get(key,[])
        if isinstance(values,list):
            alert_ioc_values.update(values)

    misp_result=compute_misp_score(
        misp_results,
        alert_iocs=alert_ioc_values
    )

    cortex_result=compute_cortex_score(cortex_results)

    hostname=decision_engine.get("hostname")
    behavior=_safe_dict(build_behavior_fingerprint(decision_engine))
    behavior_analysis=_safe_dict(analyze_behavior(hostname,behavior))

    artifact_evidence=_safe_dict(
        decision_engine.get("artifact_evidence_zero_day")
    )
    artifact_indicators=_safe_list(artifact_evidence.get("indicators"))
    artifact_reasons=_safe_list(artifact_evidence.get("reasons"))
    artifact_behavioral=_safe_dict(artifact_evidence.get("behavioral"))
    artifact_process=_safe_dict(artifact_evidence.get("process"))
    artifact_network=_safe_dict(artifact_evidence.get("network"))
    artifact_novelty=_safe_dict(artifact_evidence.get("novelty"))

    zero_day_context=decision_engine.setdefault("zero_day",{})

    if not isinstance(zero_day_context,dict):
        zero_day_context={}
        decision_engine["zero_day"]=zero_day_context

    baseline_novelty_score=_safe_number(
        behavior_analysis.get("novelty_score",0)
    )
    artifact_novelty_score=_safe_number(
        artifact_novelty.get("score",0)
    )
    novelty_score=_merge_score(
        baseline_novelty_score,
        artifact_novelty_score
    )

    baseline_new_behavior=_safe_bool(
        behavior_analysis.get("new_behavior",False)
    )
    artifact_new_behavior=(
        _has_indicator(
            artifact_indicators,
            "NEW_BEHAVIOR_FINGERPRINT"
        )
        or
        _safe_bool(
            artifact_novelty.get("new_behavior",False)
        )
    )
    new_behavior=_merge_bool(
        baseline_new_behavior,
        artifact_new_behavior
    )

    behavior_occurrences=int(
        _safe_number(
            behavior_analysis.get("behavior_occurrences",0)
        )
    )

    baseline_rare_behavior=(
        behavior_occurrences>0
        and behavior_occurrences<3
    )

    artifact_rare_behavior=_merge_bool(
        artifact_behavioral.get("rare_behavior",False),
        artifact_novelty.get("rare_behavior",False),
        _has_indicator(artifact_indicators,"RARE_BEHAVIOR")
    )

    rare_behavior=_merge_bool(
        baseline_rare_behavior,
        artifact_rare_behavior
    )

    baseline_new_process=_safe_bool(
        behavior_analysis.get("new_process",False)
    )
    artifact_new_process=_safe_bool(
        artifact_process.get("new_process",False)
    )
    new_process=_merge_bool(
        baseline_new_process,
        artifact_new_process
    )

    process_name=behavior.get("process_name") or ""
    baseline_process_known=_safe_bool(
        behavior_analysis.get("process_known",False)
    )
    baseline_unknown_process=(
        bool(process_name)
        and not baseline_process_known
    )

    artifact_unknown_process=_safe_bool(
        artifact_process.get("unknown_process",False)
    )

    unknown_process=_merge_bool(
        baseline_unknown_process,
        artifact_unknown_process
    )

    baseline_new_destination=_safe_bool(
        behavior_analysis.get("new_destination",False)
    )
    artifact_new_destination=_safe_bool(
        artifact_network.get("new_destination",False)
    )

    new_destination=_merge_bool(
        baseline_new_destination,
        artifact_new_destination
    )

    zero_day_context["novelty"]={
        "score":novelty_score,
        "new_behavior":new_behavior,
        "rare_behavior":rare_behavior,
        "new_process":new_process,
        "unknown_process":unknown_process,
        "new_parent_child":_safe_bool(
            behavior_analysis.get("new_parent_child",False)
        ),
        "new_destination":new_destination
    }

    baseline_anomaly_score=_safe_number(
        behavior_analysis.get("anomaly_score",0)
    )
    artifact_anomaly_score=_safe_number(
        artifact_evidence.get("anomaly_score",0)
    )
    behavioral_anomaly_score=_merge_score(
        baseline_anomaly_score,
        artifact_anomaly_score
    )

    suspicious_command_chain=_merge_bool(
        artifact_behavioral.get("suspicious_command_chain",False)
    )

    abnormal_execution=_merge_bool(
        artifact_behavioral.get("abnormal_execution",False)
    )

    living_off_the_land=_merge_bool(
        artifact_behavioral.get("living_off_the_land",False),
        artifact_process.get("living_off_the_land",False),
        _has_indicator(artifact_indicators,"living_off_the_land")
    )

    process_injection=_merge_bool(
        artifact_behavioral.get("process_injection",False),
        artifact_process.get("process_injection",False),
        _has_indicator(artifact_indicators,"process_injection")
    )

    persistence=_merge_bool(
        artifact_behavioral.get("persistence",False),
        _has_indicator(artifact_indicators,"persistence")
    )

    unexpected_parent_child=_merge_bool(
        behavior_analysis.get("new_parent_child",False),
        artifact_process.get("suspicious_parent",False),
        _has_indicator(
            artifact_indicators,
            "unexpected_parent_child"
        )
    )

    zero_day_context["behavioral"]={
        "anomaly_score":behavioral_anomaly_score,
        "rare_behavior":rare_behavior,
        "unexpected_parent_child":unexpected_parent_child,
        "suspicious_command_chain":suspicious_command_chain,
        "abnormal_execution":abnormal_execution,
        "living_off_the_land":living_off_the_land,
        "process_injection":process_injection,
        "persistence":persistence
    }

    process_anomaly_score=clamp(
        _safe_number(
            artifact_process.get("anomaly_score",0)
        )
    )

    suspicious_parent=_merge_bool(
        artifact_process.get("suspicious_parent",False),
        _has_indicator(
            artifact_indicators,
            "SUSPICIOUS_PARENT"
        )
    )

    unsigned_binary=_safe_bool(
        artifact_process.get("unsigned_binary",False)
    )

    zero_day_context["process"]={
        "anomaly_score":process_anomaly_score,
        "unknown_process":unknown_process,
        "new_process":new_process,
        "suspicious_parent":suspicious_parent,
        "process_injection":process_injection,
        "living_off_the_land":living_off_the_land,
        "unsigned_binary":unsigned_binary
    }

    baseline_new_ip=_safe_bool(
        behavior_analysis.get("new_ip",False)
    )
    baseline_new_domain=_safe_bool(
        behavior_analysis.get("new_domain",False)
    )
    baseline_new_port=_safe_bool(
        behavior_analysis.get("new_port",False)
    )

    artifact_new_ip=_safe_bool(
        artifact_network.get("new_ip",False)
    )
    artifact_new_domain=_safe_bool(
        artifact_network.get("new_domain",False)
    )

    artifact_new_port=_merge_bool(
        artifact_network.get("unusual_port",False),
        _has_indicator(
            artifact_indicators,
            "unusual_port"
        ),
        _has_indicator(
            artifact_indicators,
            "new_destination_port"
        )
    )

    new_ip=_merge_bool(
        baseline_new_ip,
        artifact_new_ip
    )

    new_domain=_merge_bool(
        baseline_new_domain,
        artifact_new_domain
    )

    unusual_port=_merge_bool(
        baseline_new_port,
        artifact_new_port
    )

    network_anomaly_score=clamp(
        _safe_number(
            artifact_network.get("anomaly_score",0)
        )
    )

    dns_anomaly=_safe_bool(
        artifact_network.get("dns_anomaly",False)
    )

    beaconing=_safe_bool(
        artifact_network.get("beaconing",False)
    )

    zero_day_context["network"]={
        "anomaly_score":network_anomaly_score,
        "new_ip":new_ip,
        "new_domain":new_domain,
        "unusual_port":unusual_port,
        "dns_anomaly":dns_anomaly,
        "beaconing":beaconing
    }

    baseline_quality=behavior_analysis.get(
        "baseline_quality",
        "LEARNING"
    )

    baseline_events=int(
        _safe_number(
            behavior_analysis.get("baseline_events",0)
        )
    )

    baseline_data_quality=behavior_analysis.get(
        "data_quality",
        "LIMITED"
    )

    zero_day_context["baseline"]={
        "quality":baseline_quality,
        "events":baseline_events,
        "behavior_occurrences":behavior_occurrences,
        "data_quality":baseline_data_quality
    }

    zero_day_context["behavior_fingerprint"]=behavior.get("fingerprint")

    zero_day_result=_safe_dict(
        detect_zero_day(
            decision_engine,
            misp_result,
            cortex_result
        )
    )

    zero_day_result["baseline_analysis"]={
        "novelty_score":behavior_analysis.get("novelty_score",0),
        "anomaly_score":behavior_analysis.get("anomaly_score",0),
        "process_known":behavior_analysis.get("process_known",False),
        "parent_child_known":behavior_analysis.get("parent_child_known",False),
        "destination_known":behavior_analysis.get("destination_known",False),
        "port_known":behavior_analysis.get("port_known",False),
        "new_ip":behavior_analysis.get("new_ip",False),
        "new_domain":behavior_analysis.get("new_domain",False),
        "data_quality":behavior_analysis.get("data_quality","LIMITED")
    }

    zero_day_result["baseline"]={
        "quality":baseline_quality,
        "events":baseline_events,
        "behavior_occurrences":behavior_occurrences,
        "data_quality":baseline_data_quality
    }

    zero_day_result["behavior_fingerprint"]=behavior.get("fingerprint")

    detector_indicators=_safe_list(
        zero_day_result.get("indicators")
    )
    detector_reasons=_safe_list(
        zero_day_result.get("reasons")
    )
    baseline_indicators=_safe_list(
        behavior_analysis.get("indicators")
    )
    baseline_reasons=_safe_list(
        behavior_analysis.get("reasons")
    )

    quality_only_indicators={
        "INSUFFICIENT_BEHAVIORAL_DATA"
    }

    baseline_indicators=[
        indicator
        for indicator in baseline_indicators
        if indicator not in quality_only_indicators
    ]

    baseline_reasons=[
        reason
        for reason in baseline_reasons
        if "données comportementales disponibles sont insuffisantes"
        not in reason.lower()
    ]

    zero_day_result["indicators"]=list(
        dict.fromkeys(
            detector_indicators
            + baseline_indicators
            + artifact_indicators
        )
    )

    zero_day_result["reasons"]=list(
        dict.fromkeys(
            detector_reasons
            + baseline_reasons
            + artifact_reasons
        )
    )

    misp_statistics=_safe_dict(
        misp_result.get("statistics")
    )
    cortex_statistics=_safe_dict(
        cortex_result.get("statistics")
    )

    misp_malicious=int(
        _safe_number(
            misp_statistics.get("confirmed_malicious",0)
        )
    )

    cortex_malicious=int(
        _safe_number(
            cortex_statistics.get("confirmed_malicious",0)
        )
    )

    malicious_iocs=misp_malicious+cortex_malicious

    final_score=(
        de_result.get("score",0)
        * SOURCE_WEIGHTS.get("decision_engine",0.40)
        + misp_result.get("score",0)
        * SOURCE_WEIGHTS.get("misp",0.25)
        + cortex_result.get("score",0)
        * SOURCE_WEIGHTS.get("cortex",0.20)
        + zero_day_result.get("score",0)
        * SOURCE_WEIGHTS.get("zero_day",0.15)
    )

    final_score=round(clamp(final_score))

    return {
        "final_score":final_score,
        "decision_engine":de_result,
        "misp":misp_result,
        "cortex":cortex_result,
        "zero_day":zero_day_result,
        "malicious_iocs":malicious_iocs
    }