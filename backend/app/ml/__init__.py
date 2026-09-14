"""
IsolationForest behavioral-anomaly pilot.

See docs/ml/isolation_forest_feasibility.md for the design rationale. This
package is deliberately separate from app/detection/ — feature extraction
and model training have nothing to do with the deterministic rule engine
other than the one rule (app/detection/rules/behavioral_anomaly_login.py)
that reads their output.
"""
