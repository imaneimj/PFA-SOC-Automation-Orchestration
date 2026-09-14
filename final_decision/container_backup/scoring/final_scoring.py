from scoring.decision_engine_scoring import score_decision_engine
from scoring.misp_scoring import compute_misp_score
from scoring.cortex_scoring import compute_cortex_score
from config import SOURCE_WEIGHTS


MAX_SCORE = 100


def clamp(value, minimum=0, maximum=MAX_SCORE):
    return max(minimum, min(maximum, value))


def calculate_final_score(decision_engine, misp_results, cortex_results):
    """
    Calcule le score final en combinant Decision Engine / MISP / Cortex.

    Les pondérations viennent exclusivement de config.SOURCE_WEIGHTS
    (source unique de vérité) — ne plus jamais coder les poids en dur
    ici.

    Ce module NE DÉCIDE RIEN. Il ne fait que scorer. La décision finale
    (AUTO_CONTAIN / AUTO_RESPONSE / ...) est prise exclusivement par
    decision/decision_logic.py, qui applique les garde-fous (type
    d'incident + nombre d'IOC confirmés malveillants).
    """

    de_result = score_decision_engine(decision_engine)
    misp_result = compute_misp_score(misp_results)
    cortex_result = compute_cortex_score(cortex_results)

    final_score = (
        de_result["score"] * SOURCE_WEIGHTS["decision_engine"] +
        misp_result["score"] * SOURCE_WEIGHTS["misp"] +
        cortex_result["score"] * SOURCE_WEIGHTS["cortex"]
    )

    final_score = round(clamp(final_score))

    # Total des IOC confirmés malveillants, toutes sources confondues.
    # Utilisé par decision_logic.py pour les conditions AUTO_CONTAIN /
    # AUTO_RESPONSE.
    malicious_iocs = (
        misp_result["statistics"].get("confirmed_malicious", 0) +
        cortex_result["statistics"].get("confirmed_malicious", 0)
    )

    return {
        "final_score": final_score,
        "decision_engine": de_result,
        "misp": misp_result,
        "cortex": cortex_result,
        "malicious_iocs": malicious_iocs
    }