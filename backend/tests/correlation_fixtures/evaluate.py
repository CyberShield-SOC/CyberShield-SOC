"""Compare expected vs. actual correlation groups (Sprint 6 KK-02)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from itertools import combinations

from app.services.correlation import CorrelationResult, correlate

from .cases import CorrelationFixture, ExpectedGroup


def _actual_key(group: CorrelationResult) -> tuple:
    return (group.rule_key, group.entity_type, group.entity_value, group.event_ids, group.alert_ids)


@dataclass
class FixtureResult:
    fixture: str
    category: str
    # Expected groups the engine did not produce (missed groupings).
    missed: list[tuple] = field(default_factory=list)
    # Groups the engine produced that were not expected (false groupings).
    false_groups: list[tuple] = field(default_factory=list)
    # Event pairs that must never share a group but did (false merges).
    violated_nonmatches: list[tuple[int, int]] = field(default_factory=list)
    # Groups containing a repeated event id (duplicate evidence links).
    duplicate_links: list[tuple] = field(default_factory=list)
    expected_count: int = 0
    actual_count: int = 0

    @property
    def passed(self) -> bool:
        return not (self.missed or self.false_groups or self.violated_nonmatches or self.duplicate_links)


def evaluate_fixture(fixture: CorrelationFixture) -> FixtureResult:
    actual = correlate(list(fixture.events), list(fixture.alerts), dict(fixture.policies))
    expected = Counter(group.key for group in fixture.expected_groups)
    produced = Counter(_actual_key(group) for group in actual)

    result = FixtureResult(
        fixture.name,
        fixture.category,
        expected_count=sum(expected.values()),
        actual_count=sum(produced.values()),
    )
    result.missed = sorted((expected - produced).elements())
    result.false_groups = sorted((produced - expected).elements())
    result.duplicate_links = sorted(
        _actual_key(group) for group in actual if len(set(group.event_ids)) != len(group.event_ids)
    )
    for group in actual:
        for pair in combinations(sorted(set(group.event_ids)), 2):
            if pair in {tuple(sorted(item)) for item in fixture.expected_nonmatches}:
                result.violated_nonmatches.append(pair)
    result.violated_nonmatches = sorted(set(result.violated_nonmatches))
    return result


def evaluate_all(fixtures) -> list[FixtureResult]:
    return [evaluate_fixture(fixture) for fixture in fixtures]


def summarize(results: list[FixtureResult]) -> dict:
    expected = sum(r.expected_count for r in results)
    actual = sum(r.actual_count for r in results)
    missed = sum(len(r.missed) for r in results)
    false = sum(len(r.false_groups) for r in results)
    return {
        "fixtures": len(results),
        "passed": sum(r.passed for r in results),
        "failed": sum(not r.passed for r in results),
        "expected_groups": expected,
        "actual_groups": actual,
        "missed_groupings": missed,
        "false_groupings": false,
        "nonmatch_violations": sum(len(r.violated_nonmatches) for r in results),
        "duplicate_evidence_links": sum(len(r.duplicate_links) for r in results),
        "recall": (expected - missed) / expected if expected else 1.0,
        "precision": (actual - false) / actual if actual else 1.0,
    }


def render_report(results: list[FixtureResult]) -> str:
    """Plain-text report; failed fixtures list reproducible group keys for Paul."""

    lines = [f"{'FIXTURE':58} {'CATEGORY':10} RESULT"]
    for r in results:
        lines.append(f"{r.fixture:58} {r.category:10} {'PASS' if r.passed else 'FAIL'}")
    for r in results:
        if r.passed:
            continue
        lines.append("")
        lines.append(f"[{r.fixture}]")
        for label, items in (
            ("missed grouping", r.missed),
            ("false grouping", r.false_groups),
            ("nonmatch violated (event ids)", r.violated_nonmatches),
            ("duplicate evidence link", r.duplicate_links),
        ):
            for item in items:
                lines.append(f"  {label}: {item}")
    s = summarize(results)
    lines += [
        "",
        f"{s['passed']}/{s['fixtures']} fixtures passed | "
        f"missed groupings={s['missed_groupings']} false groupings={s['false_groupings']} "
        f"nonmatch violations={s['nonmatch_violations']} duplicate links={s['duplicate_evidence_links']} | "
        f"group recall={s['recall']:.2%} precision={s['precision']:.2%}",
    ]
    return "\n".join(lines)
