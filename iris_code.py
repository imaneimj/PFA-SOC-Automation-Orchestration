import json
import ssl
import urllib.request
import urllib.error
import hashlib
import re
import ast

IRIS_HOST = "iriswebapp_nginx"
IRIS_PORT = 8443
IRIS_API_KEY = ""
BASE_URL = f"https://{IRIS_HOST}:{IRIS_PORT}"
CASES_LIST_URL = f"{BASE_URL}/manage/cases/list"
CASES_ADD_URL = f"{BASE_URL}/manage/cases/add"
SSL_CONTEXT = ssl._create_unverified_context()

def get_prepa_data():
    raw = '''$prepa_iris'''
    if not raw or raw.strip() in ("", "None", "null"):
        raise Exception("prepa_iris est vide")
    raw = raw.strip()
    try:
        data = json.loads(raw)
    except Exception:
        try:
            data = ast.literal_eval(raw)
        except Exception as e:
            raise Exception(f"Impossible de parser prepa_iris: {str(e)[:500]}")
    if not isinstance(data, dict):
        raise Exception("prepa_iris ne contient pas un objet JSON")
    return data

def normalize(value):
    if value is None:
        return ""
    if isinstance(value, str):
        value = value.strip().lower()
        value = re.sub(r"\s+", " ", value)
        return value
    return str(value).strip().lower()

def normalize_score(value):
    if value is None:
        return 0.0
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0

def get_final_score(data):
    if not isinstance(data, dict):
        return 0.0
    if data.get("final_score") is not None:
        return normalize_score(data.get("final_score"))
    if data.get("score") is not None:
        return normalize_score(data.get("score"))
    final_decision = data.get("final_decision")
    if isinstance(final_decision, dict):
        if final_decision.get("final_score") is not None:
            return normalize_score(final_decision.get("final_score"))
        if final_decision.get("score") is not None:
            return normalize_score(final_decision.get("score"))
    decision = data.get("decision")
    if isinstance(decision, dict):
        if decision.get("final_score") is not None:
            return normalize_score(decision.get("final_score"))
        if decision.get("score") is not None:
            return normalize_score(decision.get("score"))
    return 0.0

def build_fingerprint(data):
    if not isinstance(data, dict):
        data = {}
    iocs = data.get("iocs", {})
    if not isinstance(iocs, dict):
        iocs = {}
    final_score = get_final_score(data)
    fingerprint_data = {
        "rule_id": normalize(data.get("rule_id", "")),
        "incident_type": normalize(data.get("incident_type", "")),
        "hostname": normalize(data.get("hostname", "")),
        "platform": normalize(data.get("platform", "")),
        "description": normalize(data.get("description", "")),
        "ips": sorted(normalize(x) for x in iocs.get("ips", [])),
        "domains": sorted(normalize(x) for x in iocs.get("domains", [])),
        "urls": sorted(normalize(x) for x in iocs.get("urls", [])),
        "hashes": sorted(normalize(x) for x in iocs.get("hashes", [])),
        "final_score": final_score
    }
    print("[DEBUG] Données utilisées pour le fingerprint:")
    print(json.dumps(fingerprint_data, indent=2, ensure_ascii=False))
    serialized = json.dumps(
        fingerprint_data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )
    fingerprint = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    print(f"[INFO] Final Score utilisé: {final_score}")
    print(f"[INFO] Nouveau Fingerprint calculé: {fingerprint}")
    return fingerprint

def iris_request(method, url, payload=None):
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method
    )
    try:
        with urllib.request.urlopen(
            request,
            context=SSL_CONTEXT,
            timeout=20
        ) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = body[:2000]
            return status, parsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = body[:2000]
        return e.code, parsed
    except Exception as e:
        return 0, {"error": str(e)[:1000]}

def extract_cases(response):
    if isinstance(response, dict):
        data = response.get("data")
        if isinstance(data, list):
            return data
        message = response.get("message")
        if isinstance(message, list):
            return message
        if isinstance(message, dict):
            data = message.get("data")
            if isinstance(data, list):
                return data
    if isinstance(response, list):
        return response
    return []

def extract_case_id(data):
    if not isinstance(data, dict):
        return None
    for key in ("case_id", "id", "caseid"):
        if data.get(key) is not None:
            return data.get(key)
    for key in ("data", "message", "case"):
        value = data.get(key)
        if isinstance(value, dict):
            case_id = extract_case_id(value)
            if case_id is not None:
                return case_id
        elif isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, dict):
                case_id = extract_case_id(first)
                if case_id is not None:
                    return case_id
    return None

def case_matches(case, candidate):
    if not isinstance(case, dict):
        return False
    candidate_fingerprint = normalize(candidate.get("fingerprint", ""))
    if not candidate_fingerprint:
        return False
    case_description = normalize(case.get("case_description", ""))
    return candidate_fingerprint in case_description

def find_existing_case(candidate):
    print("[INFO] Recherche des cases IRIS...")
    status, response = iris_request("GET", CASES_LIST_URL)
    if status != 200:
        raise Exception(
            "Impossible de récupérer les "
            f"cases IRIS. HTTP {status}"
        )
    cases = extract_cases(response)
    fingerprint = candidate.get("fingerprint", "")
    print(f"[INFO] {len(cases)} cases récupérées")
    print(f"[INFO] Fingerprint recherché: {fingerprint}")
    for case in cases:
        if case_matches(case, candidate):
            case_id = extract_case_id(case)
            print(f"[INFO] Doublon détecté. Case ID: {case_id}")
            return case
    print("[INFO] Aucun doublon détecté")
    return None

def build_case_payload(candidate):
    hostname = candidate.get("hostname") or "Unknown Host"
    rule_id = candidate.get("rule_id") or "Unknown Rule"
    incident_type = candidate.get("incident_type") or "Incident"
    description = candidate.get("description") or ""
    iocs = candidate.get("iocs", {})
    if not isinstance(iocs, dict):
        iocs = {}
    ips = iocs.get("ips", [])
    domains = iocs.get("domains", [])
    urls = iocs.get("urls", [])
    hashes = iocs.get("hashes", [])
    if not isinstance(ips, list):
        ips = []
    if not isinstance(domains, list):
        domains = []
    if not isinstance(urls, list):
        urls = []
    if not isinstance(hashes, list):
        hashes = []
    ml = candidate.get("ml", {})
    if not isinstance(ml, dict):
        ml = {}
    response = candidate.get("response", {})
    if not isinstance(response, dict):
        response = {}
    actions = response.get("actions", [])
    if not isinstance(actions, list):
        actions = []
    case_name = f"{incident_type} - {hostname} - {rule_id}"
    final_score = get_final_score(candidate)
    case_description = f"""
============================================================
SOC INCIDENT
============================================================

{description}

============================================================
INCIDENT INFORMATION
============================================================

Incident ID: {candidate.get("incident_id", "")}
Alert ID: {candidate.get("alert_id", "")}

Hostname: {hostname}
Platform: {candidate.get("platform", "")}

Rule ID: {rule_id}
Rule Level: {candidate.get("rule_level", "")}

Incident Type: {incident_type}

Severity: {candidate.get("severity", "")}
Risk: {candidate.get("risk", "")}

Final Score: {final_score}
Decision: {candidate.get("decision", "")}
Confidence: {candidate.get("confidence", "")}

Malicious IOCs: {candidate.get("malicious_iocs", 0)}

============================================================
IOC INFORMATION
============================================================

IPs:
{json.dumps(ips, indent=2, ensure_ascii=False)}

Domains:
{json.dumps(domains, indent=2, ensure_ascii=False)}

URLs:
{json.dumps(urls, indent=2, ensure_ascii=False)}

Hashes:
{json.dumps(hashes, indent=2, ensure_ascii=False)}

============================================================
SCORING
============================================================

Decision Engine Score:
{candidate.get("decision_engine_score", 0)}

MISP Score:
{candidate.get("misp_score", 0)}

Cortex Score:
{candidate.get("cortex_score", 0)}

============================================================
MACHINE LEARNING
============================================================

Prediction:
{ml.get("prediction", "")}

Confidence:
{ml.get("confidence", "")}

Confidence Level:
{ml.get("confidence_level", "")}

Model Version:
{ml.get("model_version", "")}

============================================================
RESPONSE
============================================================

Response Required:
{candidate.get("response_required", False)}

Analyst Approval Required:
{candidate.get("analyst_approval_required", False)}

Automatic:
{response.get("automatic", False)}

Actions:
{json.dumps(actions, indent=2, ensure_ascii=False)}

============================================================
FINGERPRINT
============================================================

Fingerprint:
{candidate.get("fingerprint", "")}

Fingerprint Final Score:
{final_score}

============================================================
SOURCE
============================================================

Source:
{candidate.get("source", "Wazuh")}

""".strip()
    MAX_DESCRIPTION_SIZE = 25000
    if len(case_description.encode("utf-8")) > MAX_DESCRIPTION_SIZE:
        case_description = (
            case_description.encode("utf-8")[:MAX_DESCRIPTION_SIZE]
            .decode("utf-8", errors="ignore")
        )
        case_description += "\n\n[TRUNCATED - description trop volumineuse]"
    payload = {
        "case_name": case_name,
        "case_description": case_description,
        "case_customer": 1,
        "case_soc_id": candidate.get("incident_id", ""),
        "case_organisations": []
    }
    return payload

def create_case(candidate):
    print("[INFO] Préparation du case IRIS...")
    payload = build_case_payload(candidate)
    payload_size = len(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    print(f"[INFO] Taille payload IRIS: {payload_size} octets")
    status, response = iris_request(
        "POST",
        CASES_ADD_URL,
        payload
    )
    return {
        "status": status,
        "response": response
    }

try:
    print("[INFO] IRIS - début")
    raw_candidate = get_prepa_data()
    if isinstance(raw_candidate.get("message"), dict):
        print("[INFO] Données incident trouvées dans message")
        candidate = raw_candidate["message"].copy()
    else:
        print("[INFO] Candidate déjà normalisé")
        candidate = raw_candidate.copy()

    final_score = get_final_score(candidate)
    candidate["final_score"] = final_score
    print(f"[INFO] Final Score reçu par IRIS: {final_score}")

    candidate["fingerprint"] = build_fingerprint(candidate)
    fingerprint = candidate["fingerprint"]
    print(f"[INFO] Fingerprint final: {fingerprint}")

    duplicate = find_existing_case(candidate)

    if duplicate:
        case_id = extract_case_id(duplicate)
        result = {
            "success": True,
            "action": "CASE_EXISTS",
            "message": "Case IRIS existante - aucune création",
            "fingerprint": fingerprint,
            "final_score": final_score,
            "case_id": case_id
        }
        print(json.dumps(result, ensure_ascii=False))
    else:
        creation = create_case(candidate)
        status = creation["status"]
        response = creation.get("response", {})
        if status not in [200, 201]:
            result = {
                "success": False,
                "action": "CREATE_CASE_FAILED",
                "message": "Échec de création du case IRIS",
                "status": status,
                "fingerprint": fingerprint,
                "final_score": final_score
            }
            print(json.dumps(result, ensure_ascii=False))
        else:
            case_id = extract_case_id(response)
            result = {
                "success": True,
                "action": "CASE_CREATED",
                "message": "Case IRIS créé",
                "status": status,
                "case_id": case_id,
                "fingerprint": fingerprint,
                "final_score": final_score
            }
            print(json.dumps(result, ensure_ascii=False))
except Exception as e:
    result = {
        "success": False,
        "action": "ERROR",
        "message": str(e)[:1000]
    }
    print(json.dumps(result, ensure_ascii=False))