from typing import Any, Dict, List

from pydantic import BaseModel, Field


class FinalizeRequest(BaseModel):
    """
    Requête reçue depuis Shuffle
    """

    normalized: Dict[str, Any] = Field(default_factory=dict)
    misp: List[Any] = Field(default_factory=list)
    cortex: List[Any] = Field(default_factory=list)
    velociraptor: Dict[str, Any] = Field(default_factory=dict)


class ScoreDetails(BaseModel):
    """
    Détail du score calculé par chaque source
    """

    wazuh: float = 0
    misp: float = 0
    cortex: float = 0
    velociraptor: float = 0


class RiskResult(BaseModel):
    """
    Résultat du calcul du score
    """

    global_score: float

    risk_level: str

    details: ScoreDetails

    reasons: List[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    """
    Une action automatique
    """

    type: str

    target: str = ""

    parameters: Dict[str, Any] = Field(default_factory=dict)


class DecisionResult(BaseModel):
    """
    Décision finale
    """

    decision: str

    confidence: float

    recommended_actions: List[ResponseAction] = Field(default_factory=list)


class FinalizeResponse(BaseModel):
    """
    Réponse renvoyée à Shuffle
    """

    success: bool

    risk: RiskResult

    decision: DecisionResult