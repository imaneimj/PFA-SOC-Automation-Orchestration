from typing import Dict,List

def compute_misp_score(misp_results:List[dict],alert_iocs:set=None)->Dict:
    score=0
    reasons=[]
    alert_iocs={v.lower() for v in (alert_iocs or set())}

    statistics={
        "events":0,
        "attributes":0,
        "published_events":0,
        "ioc_matches":0,
        "confirmed_malicious":0
    }

    ioc_details={}
    confirmed_malicious_values=set()

    if not misp_results:
        return {
            "score":0,
            "risk":"LOW",
            "statistics":statistics,
            "reasons":[]
        }

    for response in misp_results:
        if not response.get("success",False):
            continue

        body=response.get("body",{})
        events=body.get("response",[])
        statistics["events"]+=len(events)

        for event_wrapper in events:
            event=event_wrapper.get("Event",{})
            threat=int(event.get("threat_level_id",4))

            if threat==1:
                score+=40
                reasons.append("Threat level : High")
            elif threat==2:
                score+=30
                reasons.append("Threat level : Medium")
            elif threat==3:
                score+=15
                reasons.append("Threat level : Low")

            if event.get("published",False):
                score+=15
                statistics["published_events"]+=1
                reasons.append("Published event")

            attributes=event.get("Attribute",[])
            statistics["attributes"]+=len(attributes)
            statistics["ioc_matches"]+=len(attributes)

            for attr in attributes:
                value=attr.get("value","")
                attr_type=attr.get("type","")
                to_ids=attr.get("to_ids",False)

                is_actual_alert_ioc=value.lower() in alert_iocs

                if to_ids and threat<=2 and is_actual_alert_ioc:
                    attr_score=10
                    confirmed_malicious_values.add(value)
                elif to_ids:
                    attr_score=5
                else:
                    attr_score=1

                score+=attr_score
                reasons.append(
                    f"MISP match : {attr_type} -> {value} "
                    f"(to_ids={to_ids})"
                )

    score=min(score,100)

    if score>=80:
        risk="CRITICAL"
    elif score>=60:
        risk="HIGH"
    elif score>=30:
        risk="MEDIUM"
    else:
        risk="LOW"

    statistics["confirmed_malicious"]=len(confirmed_malicious_values)

    return {
        "score":score,
        "risk":risk,
        "statistics":statistics,
        "ioc_details":ioc_details,
        "reasons":reasons
    }