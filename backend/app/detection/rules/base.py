from __future__ import annotations

from abc import ABC, abstractmethod

from app.detection.models import Alert, LogRecord


class BaseRule(ABC):
    @abstractmethod
    def analyze(self, records: list[LogRecord]) -> list[Alert]: ...
