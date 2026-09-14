from fastapi import FastAPI, Request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
from evidence_analyzer import process_evidence, merge_zero_day_evidences
from normalize import normalize
from classifier import classify
from planner import build_plan
from wazuh_client import get_agent
from evidence_processor import (
    flatten_ioc_dict,
    extract_velociraptor_iocs,
    merge_iocs,
    extract_iocs)
from alert_filter import _is_critical_override
from artifact_parameters import build_filefinder_parameters
from velociraptor_client import VelociraptorClient
from report_generator import EvidenceReportGenerator
from ioc_processor import (
    split_iocs,
    ioc_statistics,
    process_iocs)
from alert_filter import should_investigate
from noise_filter import is_noise
from dedup import should_collect
velo = VelociraptorClient()
app = FastAPI()
@app.get("/")
def home():
    return {"message": "Decision Engine is running"}
def normalize_platform(os_name):
    if not os_name:
        return "Unknown"
    os_name = os_name.lower()
    if ( "ubuntu" in os_name or "linux" in os_name or "debian" in os_name):
        return "Linux"
    if "windows" in os_name:
        return "Windows"
    if ("darwin" in os_name or "mac" in os_name):
        return "MacOS"
    return "Unknown"
@app.post("/decision")
async def decision(request: Request):
    try:
        print("\n========== NOUVELLE ALERTE ==========")

        alert = await request.json()

        print(
            f"[OK] JSON reçu "
            f"(id={alert.get('id')})"
        )

        normalized = normalize(alert)

        wazuh_iocs = normalized.get(
            "ioc",
            {
                "hashes": [],
                "ips": [],
                "domains": [],
                "urls": []
            }
        )

        syscheck = normalized.get("syscheck") or {}

        alert_path = str(
            syscheck.get("path", "")
        ).strip()

        alert_event = str(
            syscheck.get("event", "")
        ).strip().lower()

        print(
            "[DEBUG NOISE] path =",
            repr(alert_path)
        )

        print(
            "[DEBUG NOISE] event =",
            repr(alert_event)
        )

        print(
            "[DEBUG NOISE] rule_id =",
            repr(normalized.get("rule_id"))
        )

        print(
            "[DEBUG NOISE] groups =",
            normalized.get("groups")
        )

        if not _is_critical_override(normalized) and is_noise(alert_path):
            print(
                f"[IGNORED] Application noise filtered: "
                f"{alert_path}"
            )

            normalized["decision"] = "ignored_noise"
            normalized["ignore_reason"] = (
                "Known benign application noise"
            )

            return normalized

        hostname_early = normalized.get(
            "hostname"
        )

        rule_id_early = normalized.get(
            "rule_id"
        )

        process_name = normalized.get(
            "process_name",
            ""
        )

        command_line = normalized.get(
            "command_line",
            ""
        )

        parent_process = normalized.get(
            "parent_process",
            ""
        )

        username = normalized.get(
            "username",
            ""
        )

        ioc_early = normalized.get(
            "ioc",
            {}
        )

        if not should_collect(
            hostname=hostname_early,
            rule_id=rule_id_early,
            process_name=process_name,
            command_line=command_line,
            parent_process=parent_process,
            username=username,
            ioc=ioc_early,
        ):
            print(
                "[SKIP] Duplicate alert - same context"
            )

            normalized["decision"] = (
                "deduplicated"
            )

            return normalized

        agent_id = normalized.get(
            "agent_id"
        )

        agent = (
            get_agent(agent_id)
            if agent_id
            else {}
        )

        normalized["agent_info"] = agent
        normalized["platform"] = "Unknown"

        os_info = agent.get(
            "os",
            {}
        ) or {}

        if os_info:
            normalized["agent_os"] = os_info.get(
                "name",
                normalized.get(
                    "agent_os",
                    "Unknown"
                )
            )

            normalized["agent_os_version"] = os_info.get(
                "version",
                normalized.get(
                    "agent_os_version",
                    "Unknown"
                )
            )

            normalized["agent_architecture"] = os_info.get(
                "arch",
                normalized.get(
                    "agent_architecture",
                    "Unknown"
                )
            )

            normalized["platform"] = (
                normalize_platform(
                    normalized["agent_os"]
                )
            )

        print(
            "[OK] Enrichissement agent terminé"
        )

        classification = classify(
            normalized
        )

        normalized["incident_type"] = (
            classification.get(
                "type",
                "Unknown"
            )
        )

        normalized["classification"] = (
            classification
        )

        print(
            "================ DEBUG FILTER ================"
        )

        print(
            "GROUPS =",
            normalized.get("groups")
        )

        print(
            "SYSCHECK =",
            normalized.get("syscheck")
        )

        print(
            "PATH =",
            (
                normalized.get(
                    "syscheck"
                ) or {}
            ).get(
                "path"
            )
        )

        print(
            "RULE ID =",
            normalized.get("rule_id")
        )

        print(
            "=============================================="
        )

        if not should_investigate(
            normalized
        ):
            print(
                "[INFO] Alerte ignorée "
                "(probable faux positif)"
            )

            normalized["decision"] = (
                "ignored"
            )

            return normalized

        print(
            f"[OK] Incident classifié : "
            f"{normalized['incident_type']}"
        )

        plan = build_plan(
            normalized["incident_type"],
            normalized["platform"],
            normalized["ioc"]
        )

        normalized[
            "investigation_plan"
        ] = plan

        collections = []

        all_iocs = flatten_ioc_dict(
            wazuh_iocs,
            source="wazuh"
        )

        hostname = normalized.get(
            "hostname"
        )

        client = (
            velo.get_client_by_hostname(
                hostname
            )
            if hostname
            else None
        )

        if not plan.get(
            "investigations"
        ):
            print(
                "[i] Aucun artefact planifié "
                "pour ce type d'incident "
                "(profil vide)."
            )

        elif client:
            print(
                f"[+] Client trouvé : "
                f"{hostname}"
            )

            def run_one_collection(
                action
            ):
                artifact = action[
                    "artifact"
                ]

                parameters = action.get(
                    "parameters",
                    {}
                ).copy()

                print(
                    f"[+] Collecte : "
                    f"{artifact}"
                )

                if artifact.endswith(
                    "Search.FileFinder"
                ):
                    dynamic = (
                        build_filefinder_parameters(
                            normalized
                        )
                    )

                    if dynamic is None:
                        print(
                            "[i] FileFinder ignoré : "
                            "aucun paramètre."
                        )

                        return None

                    parameters.update(
                        dynamic
                    )

                try:
                    raw_evidence = (
                        velo.collect_artifact(
                            client["client_id"],
                            artifact,
                            parameters
                        )
                    )

                    flow_id = None
                    evidence = []

                    if isinstance(
                        raw_evidence,
                        dict
                    ):
                        flow_id = (
                            raw_evidence.get(
                                "flow_id"
                            )
                        )

                        if isinstance(
                            raw_evidence.get(
                                "results"
                            ),
                            list
                        ):
                            evidence = (
                                raw_evidence[
                                    "results"
                                ]
                            )

                        elif isinstance(
                            raw_evidence.get(
                                "result"
                            ),
                            list
                        ):
                            evidence = (
                                raw_evidence[
                                    "result"
                                ]
                            )

                        else:
                            evidence = [
                                raw_evidence
                            ]

                    elif isinstance(
                        raw_evidence,
                        list
                    ):
                        evidence = (
                            raw_evidence
                        )

                    else:
                        evidence = []

                    print(
                        f"[+] {artifact} -> "
                        f"{len(evidence)} résultats "
                        f"(flow_id={flow_id})"
                    )

                    return {
                        "artifact": artifact,
                        "flow_id": flow_id,
                        "rows": len(evidence),
                        "evidence": evidence
                    }

                except Exception as artifact_error:
                    print(
                        f"[!] Erreur lors de la "
                        f"collecte de {artifact} : "
                        f"{artifact_error}"
                    )

                    return {
                        "artifact": artifact,
                        "flow_id": None,
                        "rows": 0,
                        "evidence": []
                    }

            investigations = plan.get(
                "investigations",
                []
            )

            if investigations:
                with ThreadPoolExecutor(
                    max_workers=len(
                        investigations
                    )
                ) as executor:
                    futures = {
                        executor.submit(
                            run_one_collection,
                            action
                        ): action
                        for action in investigations
                    }
                    artifact_zero_day_evidences = []
                    for future in as_completed( futures):
                        result = (future.result())
                        if result is None:
                            continue
                        artifact = result["artifact"]
                        evidence = result["evidence"]
                        flow_id = result.get( "flow_id")
                        if evidence:
                            print(
                                f"[+] {artifact} -> "
                                f"{len(evidence)} résultats")
                            try:
                                artifact_iocs = (
                                    extract_velociraptor_iocs(
                                        evidence,
                                        source="velociraptor",
                                        alert_time=normalized.get(
                                            "timestamp"
                                        ),
                                        window_minutes=15
                                    )
                                )

                                if artifact_iocs:
                                    all_iocs.extend(
                                        artifact_iocs
                                    )

                            except Exception as ioc_error:
                                print(
                                    f"[!] Erreur extraction IOC "
                                    f"pour {artifact} : "
                                    f"{ioc_error}"
                                )

                            try:
                                artifact_analysis = process_evidence(
                                    artifact,
                                    evidence
                                )

                                artifact_zero_day_evidences.append(
                                    artifact_analysis.get("zero_day", {})
                                )

                                print(
                                    f"[ZERO-DAY] {artifact} -> "
                                    f"indicateurs : "
                                    f"{artifact_analysis.get('zero_day', {}).get('indicators', [])}"
                                )

                            except Exception as analysis_error:
                                print(
                                    f"[!] Erreur process_evidence "
                                    f"pour {artifact} : "
                                    f"{analysis_error}"
                                )

                        else:
                            print(
                                f"[!] Aucun résultat "
                                f"pour {artifact}"
                            )

                        collections.append({
                            "artifact": artifact,
                            "flow_id": flow_id,
                            "rows": len(evidence),
                            "evidence": evidence
                        })

        else:
            print(
                f"[!] Client Velociraptor "
                f"introuvable : {hostname}"
            )
        normalized["artifact_evidence_zero_day"] = merge_zero_day_evidences(
            artifact_zero_day_evidences
        )
        useful_iocs = process_iocs(
            all_iocs
        )

        normalized[
            "ioc_flat"
        ] = all_iocs

        normalized[
            "iocs"
        ] = useful_iocs

        normalized[
            "ioc_summary"
        ] = split_iocs(
            useful_iocs
        )

        normalized[
            "ioc_statistics"
        ] = ioc_statistics(
            useful_iocs
        )

        print(
            f"[OK] Incident normalisé : "
            f"{normalized['incident_type']} | "
            f"IOC total: "
            f"{normalized['ioc_statistics']['total']}"
        )

        print(
            "\n========== "
            "RÉSUMÉ COLLECTE VELOCIRAPTOR "
            "=========="
        )

        if collections:
            for c in collections:
                print(
                    f"{c['artifact']} -> "
                    f"{c['rows']} résultats "
                    f"(flow_id={c.get('flow_id')})"
                )

        else:
            print(
                "Aucune collecte effectuée "
                "pour cette alerte."
            )

        print(
            "===================================\n"
        )

        report = EvidenceReportGenerator()

        print(
            "1 - Titre"
        )

        report.add_title()

        print(
            "2 - Alert Summary"
        )

        report.add_alert(
            normalized
        )

        print(
            "3 - Classification"
        )

        report.add_classification(
            classification
        )

        print(
            "4 - Investigation Plan"
        )

        artifact_names = [
            a["artifact"]
            for a in plan.get(
                "investigations",
                []
            )
        ]

        report.add_plan(
            artifact_names
        )

        print(
            "5 - Evidence détaillée"
        )

        evidence_dict = {
            c["artifact"]: c["evidence"]
            for c in collections
        }

        report.add_evidence(
            evidence_dict
        )

        print(
            "6 - IOC Summary"
        )

        report.add_ioc(
            normalized.get(
                "ioc_summary",
                {}
            )
        )

        print(
            "7 - Assessment"
        )

        report.add_assessment()

        normalized[
            "collections"
        ] = collections

        normalized[
            "collection_count"
        ] = len(collections)

        normalized[
            "total_evidence_rows"
        ] = sum(
            c.get(
                "rows",
                0
            )
            for c in collections
        )

        filename = datetime.now().strftime(
            "incident_%Y%m%d_%H%M%S.md"
        )

        path = report.save(
            filename
        )

        print(
            f"\n[OK] Rapport généré : "
            f"{path}"
        )

        print(
            "\n========== RÉSUMÉ INCIDENT =========="
        )

        print(
            f"Host       : "
            f"{normalized.get('hostname')}"
        )

        print(
            f"Type       : "
            f"{normalized.get('incident_type')}"
        )

        print(
            f"Sévérité   : "
            f"{classification.get('severity')}"
        )

        print(
            f"Priorité   : "
            f"{plan.get('priority')}"
        )

        print(
            "\n--- Collecte Velociraptor ---"
        )

        if collections:
            for c in collections:
                status = (
                    "OK"
                    if c["rows"] > 0
                    else "vide"
                )

                print(
                    f"  {c['artifact']:<35} "
                    f"{c['rows']:>4} résultats "
                    f"({status}) "
                    f"(flow_id={c.get('flow_id')})"
                )

        else:
            print(
                "  Aucune collecte effectuée."
            )

        print(
            "\n--- IOC détectés ---"
        )

        if useful_iocs:
            for ioc in useful_iocs:
                src = ioc.get(
                    "source",
                    "?"
                )

                score = ioc.get(
                    "score",
                    "-"
                )

                print(
                    f"  "
                    f"[{ioc['type'].upper():<7}] "
                    f"{ioc['value']:<50} "
                    f"(source={src}, "
                    f"score={score})"
                )

        else:
            print(
                "  Aucun IOC détecté."
            )

        stats = normalized[
            "ioc_statistics"
        ]

        print(
            f"\nTotal IOC : "
            f"{stats['total']} "
            f"(hashes={stats['hashes']}, "
            f"ips={stats['ips']}, "
            f"domains={stats['domains']}, "
            f"urls={stats['urls']})"
        )

        print(
            "======================================\n"
        )

        print(
            f"[OK] Rapport généré : "
            f"{path}\n"
        )
        # ============================================================
        # RÉCUPÉRATION DU CONTENU DU RAPPORT D'INVESTIGATION
        # ============================================================

        try:
            with open(path, "r", encoding="utf-8") as f:
                investigation_report = f.read()

            # Ajouter le contenu complet du rapport dans normalized
            normalized["investigation_report"] = investigation_report

            # Le nom du fichier peut également être conservé à titre informatif
            normalized["investigation_report_filename"] = filename

            print(
                f"[OK] Rapport d'investigation récupéré "
                f"({len(investigation_report)} caractères)"
            )

        except Exception as e:
            print(f"[WARN] Impossible de lire le rapport généré : {e}")

            # On évite que le pipeline plante si la lecture échoue
            normalized["investigation_report"] = ""
            normalized["investigation_report_filename"] = filename


        return normalized

    except Exception as e:
        print(
            "\n[ERREUR]"
        )

        print(
            f"Type : {type(e).__name__}"
        )

        print(
            f"Message : {e}"
        )

        return {
            "status": "error",
            "message": str(e)
        }