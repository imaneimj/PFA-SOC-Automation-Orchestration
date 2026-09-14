from typing import Any, Dict, List

from pydantic import BaseModel, Field

class FinalizeRequest(BaseModel):
    normalized: Dict[str, Any] = Field(default_factory=dict)
    misp: List[Any] = Field(default_factory=list)
    cortex: List[Any] = Field(default_factory=list)
    velociraptor: Dict[str, Any] = Field(default_factory=dict)

class ScoreDetails(BaseModel):
    wazuh: float = 0
    misp: float = 0
    cortex: float = 0
    velociraptor: float = 0

class RiskResult(BaseModel):
    global_score: float
    risk_level: str
    details: ScoreDetails
    reasons: List[str] = Field(default_factory=list)
class ResponseAction(BaseModel):

    type: str

    target: str = ""

    parameters: Dict[str, Any] = Field(default_factory=dict)


class DecisionResult(BaseModel):

    decision: str

    confidence: float

    recommended_actions: List[ResponseAction] = Field(default_factory=list)


class FinalizeResponse(BaseModel):
    success: bool

    risk: RiskResult

    decision: DecisionResult