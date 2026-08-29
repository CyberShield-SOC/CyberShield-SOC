from fastapi import APIRouter, Depends

from app.core.config import settings
from app.detection import DetectionEngine
from app.models.user import User
from app.security import require_roles


router = APIRouter(tags=["Detection"])


@router.get("/detection/rules")
def get_detection_rules(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
):
    """Return Detection Engine v2 rule metadata and active thresholds."""

    engine = DetectionEngine.from_config(settings.detection_rule_config)
    return {
        "success": True,
        "rules": [
            metadata.model_dump()
            for metadata in engine.rule_metadata()
        ],
    }
