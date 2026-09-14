import json
import time
import requests

CORTEX_URL = "http://cortex:9001"
API_KEY = ""  

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

ANALYZER_MAP = {
    "ip": ["ad6943cc525f2b0b5b9b72d9b54438e3", "6fca8d5c8b5939914c3d04e55e08affe"],
    "url": ["af222c2f9c24602f7f72352db4eec792", "6fca8d5c8b5939914c3d04e55e08affe"],
    "hash": ["c09a42f53b9efbb418013a024ab27ef2", "6fca8d5c8b5939914c3d04e55e08affe"],
    "domain": ["af222c2f9c24602f7f72352db4eec792", "6fca8d5c8b5939914c3d04e55e08affe"]
}

iocs = json.loads('''$filter_list.valid''')

results = []

for ioc in iocs:
    ioc_type = ioc["type"]
    for analyzer_id in ANALYZER_MAP.get(ioc_type, []):
        run_resp = requests.post(
            f"{CORTEX_URL}/api/analyzer/{analyzer_id}/run",
            headers=HEADERS,
            json={
                "data": ioc["value"],
                "dataType": ioc_type,
                "tlp": 2,
                "message": "Auto-enrichissement Shuffle"
            },
            verify=False,
            timeout=15
        )

        if run_resp.status_code not in (200, 201):
            results.append({
                "ioc": ioc["value"],
                "analyzerId": analyzer_id,
                "error": f"run failed: {run_resp.status_code} {run_resp.text}"
            })
            continue
        job_id = run_resp.json().get("id")
        report = None
        for _ in range(6):
            time.sleep(5)
            rep_resp = requests.get(
                f"{CORTEX_URL}/api/job/{job_id}/report",
                headers=HEADERS,
                verify=False,
                timeout=15
            )
            if rep_resp.status_code == 200:
                data = rep_resp.json()
                if data.get("status") in ("Success", "Failure"):
                    report = data
                    break
        if not report:
            results.append({
                "ioc": ioc["value"],
                "analyzerId": analyzer_id,
                "error": "timeout waiting for job"
            })
            continue
        taxonomies = report.get("report", {}).get("summary", {}).get("taxonomies", [])
        for tax in taxonomies:
            results.append({
                "ioc": ioc["value"],
                "analyzerId": analyzer_id,
                "level": tax.get("level"),
                "namespace": tax.get("namespace"),
                "predicate": tax.get("predicate"),
                "value": tax.get("value")
            })

print(json.dumps(results))
exit(0)