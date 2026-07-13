from fastapi import APIRouter, Depends

from app.detection.alert_store import list_alerts
from app.models.user import User
from app.security import require_roles

router = APIRouter(tags=["Alerts"])


@router.get("/alerts")
def get_alerts(user: User = Depends(require_roles("Admin", "Analyst", "Viewer"))):
    return {
        "success": True,
        "alerts": list_alerts(),
    }
