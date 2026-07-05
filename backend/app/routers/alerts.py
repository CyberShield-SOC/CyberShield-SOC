from fastapi import APIRouter

from app.detection.alert_store import get_alerts

router = APIRouter(tags=["Alerts"])


@router.get("/alerts")
def list_alerts():
    alerts = get_alerts()
    return {
        "success": True,
        "total_alerts": len(alerts),
        "alerts": alerts,
    }
