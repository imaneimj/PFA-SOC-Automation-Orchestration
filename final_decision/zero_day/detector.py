from typing import Any,Dict
from config import ZERO_DAY_BASELINE

MAX_SCORE=100

def _safe_dict(value):
    return value if isinstance(value,dict) else {}

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

def _clamp(value,minimum=0,maximum=MAX_SCORE):
    return max(minimum,min(maximum,value))

def _extract_context(observation:Dict[str,Any]):
    observation=_safe_dict(observation)
    zero_day=_safe_dict(observation.get("zero_day"))

    behavioral=_safe_dict(zero_day.get("behavioral"))
    if not behavioral:
        behavioral=_safe_dict(observation.get("behavioral"))
    if not behavioral:
        behavioral=_safe_dict(observation.get("behavior"))

    network=_safe_dict(zero_day.get("network"))
    if not network:
        network=_safe_dict(observation.get("network"))
    if not network:
        network=_safe_dict(observation.get("network_analysis"))

    process=_safe_dict(zero_day.get("process"))
    if not process:
        process=_safe_dict(observation.get("process"))
    if not process:
        process=_safe_dict(observation.get("process_analysis"))

    novelty=_safe_dict(zero_day.get("novelty"))
    if not novelty:
        novelty=_safe_dict(observation.get("novelty"))
    if not novelty:
        novelty=_safe_dict(observation.get("novelty_analysis"))

    baseline=_safe_dict(zero_day.get("baseline"))

    return {
        "behavioral":behavioral,
        "network":network,
        "process":process,
        "novelty":novelty,
        "baseline":baseline
    }

def _calculate_behavioral_component(context):
    behavioral=context["behavioral"]
    score=0.0
    indicators=[]
    reasons=[]

    if _safe_bool(behavioral.get("suspicious_command_chain")):
        score+=15
        indicators.append("SUSPICIOUS_COMMAND_CHAIN")
        reasons.append("Suspicious command chain detected")

    if _safe_bool(behavioral.get("abnormal_execution")):
        score+=10
        indicators.append("ABNORMAL_EXECUTION")
        reasons.append("Abnormal execution behavior detected")

    if _safe_bool(behavioral.get("living_off_the_land")):
        score+=10
        indicators.append("LIVING_OFF_THE_LAND")
        reasons.append("Living-off-the-land behavior detected")

    if _safe_bool(behavioral.get("process_injection")):
        score+=20
        indicators.append("PROCESS_INJECTION")
        reasons.append("Process injection behavior detected")

    if _safe_bool(behavioral.get("persistence")):
        score+=15
        indicators.append("PERSISTENCE")
        reasons.append("Persistence behavior detected")

    return {
        "score":_clamp(score),
        "indicators":indicators,
        "reasons":reasons
    }

def _calculate_novelty_component(context):
    novelty=context["novelty"]
    score=0.0
    indicators=[]
    reasons=[]

    if _safe_bool(novelty.get("new_behavior")):
        score+=35
        indicators.append("NEW_BEHAVIOR_FINGERPRINT")
        reasons.append("New behavioral fingerprint detected")

    if _safe_bool(novelty.get("rare_behavior")):
        score+=10
        indicators.append("RARE_BEHAVIOR")
        reasons.append("Rare behavior detected")

    if _safe_bool(novelty.get("immature_behavior")):
        score+=5
        indicators.append("IMMATURE_HISTORY")
        reasons.append("Behavior has insufficient historical maturity")

    if _safe_bool(novelty.get("new_process")):
        score+=20
        indicators.append("NEW_PROCESS")
        reasons.append("New process detected")

    if _safe_bool(novelty.get("new_parent_process")):
        score+=20
        indicators.append("NEW_PARENT_PROCESS_RELATION")
        reasons.append("New parent-process relationship detected")

    if _safe_bool(novelty.get("new_destination")):
        score+=15
        indicators.append("NEW_DESTINATION")
        reasons.append("New network destination detected")

    if _safe_bool(novelty.get("new_port")):
        score+=10
        indicators.append("NEW_PORT")
        reasons.append("New network port detected")

    return {
        "score":_clamp(score),
        "indicators":indicators,
        "reasons":reasons
    }

def _calculate_network_component(context):
    network=context["network"]
    score=0.0
    indicators=[]
    reasons=[]

    if _safe_bool(network.get("new_ip")):
        score+=15
        indicators.append("NEW_IP")
        reasons.append("New IP address detected")

    if _safe_bool(network.get("new_domain")):
        score+=15
        indicators.append("NEW_DOMAIN")
        reasons.append("New domain detected")

    if _safe_bool(network.get("unusual_port")):
        score+=15
        indicators.append("UNUSUAL_PORT")
        reasons.append("Unusual network port detected")

    if _safe_bool(network.get("beaconing")):
        score+=20
        indicators.append("BEACONING")
        reasons.append("Beaconing behavior detected")

    return {
        "score":_clamp(score),
        "indicators":indicators,
        "reasons":reasons
    }

def _calculate_process_component(context):
    process=context["process"]
    score=0.0
    indicators=[]
    reasons=[]

    if _safe_bool(process.get("unknown_process")):
        score+=20
        indicators.append("UNKNOWN_PROCESS")
        reasons.append("Unknown process detected")

    if _safe_bool(process.get("suspicious_parent")):
        score+=20
        indicators.append("SUSPICIOUS_PARENT")
        reasons.append("Suspicious parent process detected")

    if _safe_bool(process.get("process_injection")):
        score+=25
        indicators.append("PROCESS_INJECTION")
        reasons.append("Process injection detected")

    if _safe_bool(process.get("living_off_the_land")):
        score+=15
        indicators.append("LIVING_OFF_THE_LAND")
        reasons.append("Living-off-the-land process detected")

    if _safe_bool(process.get("unsigned_binary")):
        score+=10
        indicators.append("UNSIGNED_BINARY")
        reasons.append("Unsigned binary detected")

    return {
        "score":_clamp(score),
        "indicators":indicators,
        "reasons":reasons
    }

def detect_zero_day(observation:Dict[str,Any]):
    context=_extract_context(observation)

    behavioral=_calculate_behavioral_component(context)
    novelty=_calculate_novelty_component(context)
    network=_calculate_network_component(context)
    process=_calculate_process_component(context)

    components={
        "behavioral_anomaly":behavioral,
        "novelty":novelty,
        "network_anomaly":network,
        "process_anomaly":process
    }

    raw_score=(
        behavioral["score"]*0.35
        +novelty["score"]*0.25
        +network["score"]*0.20
        +process["score"]*0.20
    )

    indicators=[]
    reasons=[]

    for component in components.values():
        indicators.extend(component["indicators"])
        reasons.extend(component["reasons"])

    baseline=context["baseline"]

    baseline_quality=str(
        baseline.get("quality","LEARNING")
    ).upper()

    baseline_events=int(
        _safe_number(baseline.get("events",0))
    )

    active_components=sum(
        1
        for component in components.values()
        if component["score"]>=25
    )

    misp_malicious=int(
        _safe_number(
            _safe_dict(
                observation.get("misp")
            ).get("malicious",0)
        )
    )

    cortex_malicious=int(
        _safe_number(
            _safe_dict(
                observation.get("cortex")
            ).get("malicious",0)
        )
    )

    known_reputation=(
        misp_malicious>0
        or cortex_malicious>0
    )

    if not known_reputation and active_components>=3:
        raw_score+=8
        indicators.append("NO_KNOWN_REPUTATION")
        reasons.append(
            "No known malicious reputation combined "
            "with multiple behavioral anomalies"
        )

    learning_multiplier=_safe_number(
        ZERO_DAY_BASELINE.get(
            "learning_score_multiplier",
            0.60
        ),
        0.60
    )

    weak_multiplier=_safe_number(
        ZERO_DAY_BASELINE.get(
            "weak_score_multiplier",
            0.85
        ),
        0.85
    )

    mature_bonus=_safe_number(
        ZERO_DAY_BASELINE.get(
            "mature_bonus",
            5
        ),
        5
    )

    if baseline_quality=="LEARNING":
        raw_score*=learning_multiplier
    elif baseline_quality=="WEAK":
        raw_score*=weak_multiplier
    elif baseline_quality=="MATURE" and active_components>=2:
        raw_score+=mature_bonus

    final_score=round(
        _clamp(raw_score),
        2
    )

    if final_score<30:
        risk="LOW"
    elif final_score<60:
        risk="MEDIUM"
    elif final_score<80:
        risk="HIGH"
    else:
        risk="CRITICAL"

    suspected=(
        final_score>=60
        and active_components>=2
    )

    indicator_count=len(indicators)

    if indicator_count>=7:
        confidence=0.90
    elif indicator_count>=5:
        confidence=0.80
    elif indicator_count>=3:
        confidence=0.70
    elif indicator_count>=1:
        confidence=0.55
    else:
        confidence=0.20

    if active_components>=3:
        confidence+=0.05

    confidence=min(confidence,0.95)

    return {
        "score":final_score,
        "risk":risk,
        "confidence":round(confidence,2),
        "suspected":suspected,
        "indicators":indicators,
        "reasons":reasons,
        "components":{
            "behavioral_anomaly":behavioral["score"],
            "novelty":novelty["score"],
            "network_anomaly":network["score"],
            "process_anomaly":process["score"]
        },
        "metadata":{
            "detector_version":"2.1.0",
            "misp_malicious":misp_malicious,
            "cortex_malicious":cortex_malicious,
            "active_components":active_components,
            "baseline_quality":baseline_quality,
            "baseline_events":baseline_events
        },
        "baseline":{
            "quality":baseline_quality,
            "events":baseline_events
        }
    }