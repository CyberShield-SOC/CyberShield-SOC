from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.detection import DetectionEngine
from app.models.user import User
from app.repositories.detection_rule_setting_repository import (
    DetectionRuleNotFoundError,
    effective_rule_configs,
    upsert_rule_setting,
)
from app.schemas.detection_rule import DetectionRuleUpdate
from app.security import require_roles


router = APIRouter(tags=["Detection"])


@router.get("/detection/rules")
def get_detection_rules(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Return Detection Engine v2 rule metadata and active thresholds.

    Active thresholds reflect, per rule, the class default overridden first
    by DETECTION_RULE_CONFIG and then by any admin-saved setting — the same
    precedence _run_upload_pipeline uses to build the engine.
    """

    configs = effective_rule_configs(db, settings.detection_rule_config)
    engine = DetectionEngine.from_config({name: config.model_dump() for name, config in configs.items()})
    enabled_by_name = {rule.name: rule for rule in engine.rules}

    rules = []
    for name, config in configs.items():
        rule = enabled_by_name.get(name)
        description = rule.description if rule is not None else name.replace("_", " ").title()
        severity = rule.severity if rule is not None else "MEDIUM"
        rules.append({
            "name": name,
            "description": description,
            "severity": severity,
            "config": config.model_dump(),
        })

    return {"success": True, "rules": rules}


@router.patch("/detection/rules/{rule_name}")
def patch_detection_rule(
    rule_name: str,
    payload: DetectionRuleUpdate,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Persist an enabled/threshold override for one built-in rule.

    Takes effect on the next upload — DetectionEngine is rebuilt per upload
    from the same effective_rule_configs this endpoint writes through.
    """

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No rule settings were provided.")

    try:
        upsert_rule_setting(db, rule_name=rule_name, updates=updates, updated_by=user.id)
        db.commit()
    except DetectionRuleNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Detection rule setting could not be saved.") from exc

    configs = effective_rule_configs(db, settings.detection_rule_config)
    return {"success": True, "rule": {"name": rule_name, "config": configs[rule_name].model_dump()}}
