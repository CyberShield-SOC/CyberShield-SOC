from app.detection.models import Alert, LogRecord

# DetectionEngine is deliberately NOT re-exported here (import it from
# app.detection.engine directly). This package's __init__ runs whenever
# anything imports any app.detection submodule (e.g. app.detection._ts),
# and importing engine.py here would eagerly pull in every rule module —
# including the behavioral_anomaly_* rules, which import app.ml.pipeline.
# Anything that itself reaches app.detection through that path (as
# app.repositories.ml_repository does) would hit a circular import the
# moment app.ml.pipeline is the entry point, e.g. `python -m
# app.ml.train_login_behavior`.
__all__ = ["Alert", "LogRecord"]
