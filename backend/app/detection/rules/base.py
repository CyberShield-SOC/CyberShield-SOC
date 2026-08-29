from __future__ import annotations

from abc import ABC, abstractmethod

from app.detection.models import Alert, LogRecord, RuleConfig, RuleMetadata


class BaseRule(ABC):
    name: str
    description: str
    severity: str

    @property
    def config(self) -> RuleConfig:
        return RuleConfig(
            threshold=getattr(self, "threshold", None),
            fail_threshold=getattr(self, "fail_threshold", None),
            window_seconds=getattr(self, "window_seconds", None),
            success_window_seconds=getattr(self, "success_window_seconds", None),
            enabled=True,
        )

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            name=self.name,
            description=self.description,
            severity=self.severity,
            config=self.config,
        )

    @abstractmethod
    def analyze(self, records: list[LogRecord]) -> list[Alert]: ...
