from pydantic import BaseModel
from typing import List, Optional
from enum import Enum

class RiskVerdict(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class AppAnalyzeRequest(BaseModel):
    app_id: str
    source: str = "play_store"

class FlaggedReason(BaseModel):
    signal: str
    detail: str
    weight: float

class AppAnalyzeResponse(BaseModel):
    app_id: str
    app_name: Optional[str] = None
    risk_score: float
    verdict: RiskVerdict
    flagged_reasons: List[FlaggedReason]
    is_registered: bool
    explanation: str
    analyzed_at: str

class AlertOut(BaseModel):
    alert_id: str
    app_id: str
    verdict: RiskVerdict
    risk_score: float
    message: str
    created_at: str
