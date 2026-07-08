from fastapi import APIRouter

from app.detection.alert_store import list_alerts

router = APIRouter(tags=["Alerts"])


@router.get("/alerts")
def get_alerts():
    return {
        "success": True,
        "alerts": list_alerts(),
    }
