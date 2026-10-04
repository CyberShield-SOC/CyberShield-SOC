"""Detection / false-positive metrics for scored scenarios.

Scores are IsolationForest decision_function values in the backend's native
form: below 0 is anomalous, and lower (more negative) is more anomalous. A
threshold flags everything strictly below it. Nothing here rescales a score.
"""

from __future__ import annotations

import platform
from collections.abc import Iterable, Mapping


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion (well behaved at 0 and at small n)."""

    if n == 0:
        return (0.0, 0.0)
    phat = successes / n
    denom = 1 + z**2 / n
    centre = phat + z**2 / (2 * n)
    margin = z * ((phat * (1 - phat) / n + z**2 / (4 * n**2)) ** 0.5)
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def flagged(scores: Iterable[float], threshold: float) -> int:
    return sum(1 for score in scores if score < threshold)


def rate(scores: list[float], threshold: float) -> dict:
    """Share of `scores` flagged at `threshold`, with its Wilson interval."""

    hits, n = flagged(scores, threshold), len(scores)
    low, high = wilson_ci(hits, n)
    return {"flagged": hits, "n": n, "rate": (hits / n) if n else 0.0, "ci_low": low, "ci_high": high}


def sweep(normal: list[float], attack_groups: Mapping[str, list[float]], thresholds: Iterable[float]) -> list[dict]:
    """False-positive rate on normal data and detection rate per attack group, per threshold."""

    rows = []
    for threshold in thresholds:
        row = {"threshold": threshold, "fp": rate(normal, threshold)}
        for group, scores in attack_groups.items():
            row[group] = rate(scores, threshold)
        rows.append(row)
    return rows


def roc_auc(normal: list[float], attacks: list[float]) -> float:
    """Probability a random attack scores lower (more anomalous) than a random normal point."""

    from sklearn.metrics import roc_auc_score

    labels = [0] * len(normal) + [1] * len(attacks)
    # More anomalous = lower score, so negate to make "higher = more anomalous".
    return float(roc_auc_score(labels, [-s for s in normal + attacks]))


def separation_margin(normal: list[float], attacks: list[float]) -> float:
    """min(normal) - max(attack): positive means every attack scores below every normal point."""

    return min(normal) - max(attacks)


def environment_versions() -> dict[str, str]:
    """Recorded in every report: scores can shift slightly across library versions."""

    import numpy
    import sklearn

    return {
        "scikit-learn": sklearn.__version__,
        "numpy": numpy.__version__,
        "python": platform.python_version(),
    }
