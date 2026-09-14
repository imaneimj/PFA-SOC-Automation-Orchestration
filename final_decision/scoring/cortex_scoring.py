import re
from typing import Dict,List

def compute_cortex_score(cortex_results:List[dict])->Dict:
    score=0
    reasons=[]
    statistics={
        "ioc_count":0,
        "malicious":0,
        "suspicious":0,
        "safe":0,
        "info":0,
        "confirmed_malicious":0
    }
    ioc_details={}
    confirmed_malicious_iocs=set()

    if not cortex_results:
        return {
            "score":0,
            "risk":"LOW",
            "statistics":statistics,
            "ioc_details":{},
            "reasons":[]
        }

    for item in cortex_results:
        ioc=item.get("ioc","unknown")
        namespace=item.get("namespace","")
        predicate=item.get("predicate","")
        level=item.get("level","info")
        value=item.get("value","")

        if ioc not in ioc_details:
            ioc_details[ioc]=[]

        ioc_details[ioc].append(item)
        statistics[level]=statistics.get(level,0)+1

        if namespace=="VT":
            if isinstance(value,str):
                match=re.search(r"(\d+)/(\d+)",value)

                if match:
                    positives=int(match.group(1))

                    if positives==0:
                        vt_score=0
                    elif positives<=2:
                        vt_score=15
                    elif positives<=5:
                        vt_score=30
                    elif positives<=10:
                        vt_score=50
                    else:
                        vt_score=70

                    score+=vt_score
                    reasons.append(f"VirusTotal : {positives} détection(s)")

                    if positives>=5:
                        confirmed_malicious_iocs.add(ioc)

        elif namespace=="AbuseIPDB" and predicate=="Score":
            try:
                abuse_score=int(value)
            except Exception:
                abuse_score=0

            if abuse_score>=75:
                score+=50
            elif abuse_score>=50:
                score+=35
            elif abuse_score>=25:
                score+=20
            elif abuse_score>0:
                score+=10

            reasons.append(f"AbuseIPDB score : {abuse_score}")

            if abuse_score>=50:
                confirmed_malicious_iocs.add(ioc)

        elif namespace=="AbuseIPDB" and predicate=="Reports":
            try:
                reports=int(value)
            except Exception:
                reports=0

            if reports>0:
                score+=min(reports*2,20)
                reasons.append(f"AbuseIPDB : {reports} report(s)")

    score=max(0,min(score,100))

    if score>=80:
        risk="CRITICAL"
    elif score>=60:
        risk="HIGH"
    elif score>=30:
        risk="MEDIUM"
    else:
        risk="LOW"

    statistics["ioc_count"]=len(ioc_details)
    statistics["confirmed_malicious"]=len(confirmed_malicious_iocs)

    return {
        "score":score,
        "risk":risk,
        "statistics":statistics,
        "ioc_details":ioc_details,
        "reasons":reasons
    }