from fastapi import APIRouter

router = APIRouter()

@router.get("/alerts")
def get_alerts():
    return {"alerts": [], "message": "Alert system coming in Week 3"}
