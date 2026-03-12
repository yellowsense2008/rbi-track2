from fastapi import APIRouter
from models.schemas import AppAnalyzeRequest, AppAnalyzeResponse, RiskVerdict, FlaggedReason
from datetime import datetime

router = APIRouter()

@router.post("/analyze", response_model=AppAnalyzeResponse)
async def analyze_app(request: AppAnalyzeRequest):
    # Stub — returns mock response until services are wired in
    return AppAnalyzeResponse(
        app_id=request.app_id,
        app_name="Test App",
        risk_score=0.0,
        verdict=RiskVerdict.LOW,
        flagged_reasons=[],
        is_registered=False,
        explanation="Analysis pipeline not yet connected.",
        analyzed_at=datetime.utcnow().isoformat()
    )
