from __future__ import annotations

from abc import ABC, abstractmethod
from inspect import signature
from typing import TYPE_CHECKING, Any, ClassVar

from app.detection.models import Alert, EntityType, LogRecord, ParamValue, RuleConfig, RuleMetadata

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

# Config fields every rule honours regardless of its __init__ signature:
# enabled/confidence are applied by the engine, cooldown by alert suppression.
ALWAYS_TUNABLE = ("enabled", "confidence", "cooldown_seconds")


class BaseRule(ABC):
    name: str
    description: str
    severity: str
    # MITRE ATT&CK technique ID this rule corresponds to, e.g. "T1110.001".
    mitre_technique: str = ""
    # What entity this rule pivots its grouping/count/window on.
    entity_type: EntityType = "source_ip"
    # Default detection-confidence (0-100), independent of severity.
    confidence: int = 70
    # Rule-specific tunables and their defaults. A rule that declares any
    # accepts `params` in __init__ and reads merged values from self.params.
    DEFAULT_PARAMS: ClassVar[dict[str, ParamValue]] = {}

    def merge_params(self, overrides: dict[str, Any] | None) -> dict[str, ParamValue]:
        """Defaults overlaid with known, type-coerced overrides.

        Unknown keys are ignored here (the API rejects them before they are
        stored); a value that can't be coerced to the default's type keeps
        the default rather than crashing detection for every upload.
        """

        merged = dict(self.DEFAULT_PARAMS)
        for key, value in (overrides or {}).items():
            if key not in self.DEFAULT_PARAMS or value is None:
                continue
            default = self.DEFAULT_PARAMS[key]
            try:
                if isinstance(default, bool):
                    merged[key] = value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
                elif isinstance(default, int):
                    merged[key] = int(value)
                elif isinstance(default, float):
                    merged[key] = float(value)
                else:
                    merged[key] = str(value)
            except (TypeError, ValueError):
                continue
        return merged

    @property
    def config(self) -> RuleConfig:
        return RuleConfig(
            threshold=getattr(self, "threshold", None),
            fail_threshold=getattr(self, "fail_threshold", None),
            window_seconds=getattr(self, "window_seconds", None),
            success_window_seconds=getattr(self, "success_window_seconds", None),
            cooldown_seconds=getattr(self, "cooldown_seconds", None),
            confidence=getattr(self, "confidence", None),
            allowlist=getattr(self, "allowlist", None),
            start_hour=getattr(self, "start_hour", None),
            end_hour=getattr(self, "end_hour", None),
            params=dict(getattr(self, "params", None) or {}) or None,
            enabled=True,
        )

    @classmethod
    def tunables(cls) -> list[str]:
        accepted = set(signature(cls).parameters) & set(RuleConfig.model_fields)
        return [field for field in RuleConfig.model_fields if field in accepted or field in ALWAYS_TUNABLE]

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            name=self.name,
            description=self.description,
            severity=self.severity,
            config=self.config,
            mitre_technique=self.mitre_technique or None,
            entity_type=self.entity_type,
            tunables=self.tunables(),
        )

    @abstractmethod
    def analyze(self, records: list[LogRecord], db: "Session | None" = None) -> list[Alert]:
        """
        Run this rule against one upload's records.

        `db` is optional and ignored by nearly every rule — it exists only
        for the small number of rules that read/write cross-upload state
        (baselines, host heartbeats, threat-intel indicators). A rule that
        needs it must still behave sensibly (usually: batch-only, or no
        alerts) when it is None.
        """
        ...
