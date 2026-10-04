"""KK-01 / KK-02: run every correlation fixture through the real engine."""

from dataclasses import replace

import pytest

from app.services.correlation import correlate
from tests.correlation_fixtures import (
    FIXTURES,
    ExpectedGroup,
    evaluate_all,
    evaluate_fixture,
    render_report,
    summarize,
)
from tests.correlation_fixtures.cases import CATEGORIES

pytestmark = pytest.mark.no_db

BY_NAME = {fixture.name: fixture for fixture in FIXTURES}


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f.name)
def test_fixture_matches_engine(fixture):
    result = evaluate_fixture(fixture)
    assert result.passed, render_report([result])


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f.name)
def test_fixture_result_is_input_order_independent(fixture):
    forward = correlate(list(fixture.events), list(fixture.alerts), dict(fixture.policies))
    reverse = correlate(list(reversed(fixture.events)), list(reversed(fixture.alerts)), dict(fixture.policies))
    assert forward == reverse


def test_every_category_is_covered_and_names_are_unique():
    assert {f.category for f in FIXTURES} == set(CATEGORIES)
    assert len(BY_NAME) == len(FIXTURES)


def test_fixtures_are_well_formed():
    for fixture in FIXTURES:
        assert fixture.description and fixture.window_behavior, fixture.name
        event_ids = {event.id for event in fixture.events}
        for left, right in fixture.expected_nonmatches:
            assert {left, right} <= event_ids, f"{fixture.name}: nonmatch cites unknown event"
        for expected in fixture.expected_groups:
            assert set(expected.event_ids) <= event_ids, fixture.name
            assert set(expected.alert_ids) <= {alert.id for alert in fixture.alerts}, fixture.name


def test_issue_requested_cases_are_present():
    """Same IP / user / host, in+out of window, duplicates, normal, suspicious multi-event."""

    required = {
        "same_source_ip_in_window",
        "same_username_in_window",
        "same_host_in_window",
        "boundary_exactly_window_seconds_is_inclusive",
        "same_ip_outside_window",
        "duplicate_event_references_collapse",
        "normal_activity_without_alert",
        "suspicious_multi_event_brute_force_then_success",
    }
    assert required <= set(BY_NAME)


def test_summary_is_clean_for_current_engine():
    summary = summarize(evaluate_all(FIXTURES))
    assert summary["failed"] == 0
    assert summary["missed_groupings"] == summary["false_groupings"] == 0
    assert summary["recall"] == summary["precision"] == 1.0


# ----- the evaluator itself must be able to fail (otherwise a green run proves nothing)
def test_evaluator_reports_missed_grouping():
    fixture = BY_NAME["same_source_ip_in_window"]
    extra = ExpectedGroup("brute_force", "source_ip", "192.0.2.99", (99,), (1,))
    result = evaluate_fixture(replace(fixture, expected_groups=fixture.expected_groups + (extra,)))
    assert not result.passed and result.missed == [extra.key]


def test_evaluator_reports_false_grouping():
    fixture = BY_NAME["same_source_ip_in_window"]
    result = evaluate_fixture(replace(fixture, expected_groups=()))
    assert not result.passed and len(result.false_groups) == 1


def test_evaluator_reports_violated_nonmatch():
    fixture = BY_NAME["same_source_ip_in_window"]
    result = evaluate_fixture(replace(fixture, expected_nonmatches=((1, 2),)))
    assert result.violated_nonmatches == [(1, 2)]


def test_evaluator_boundary_catches_wrong_window_rule():
    """If the engine ever became exclusive at the edge, the inclusive fixture must fail."""

    fixture = BY_NAME["boundary_exactly_window_seconds_is_inclusive"]
    split = (
        ExpectedGroup("brute_force", "source_ip", "192.0.2.10", (1,), (1,)),
        ExpectedGroup("brute_force", "source_ip", "192.0.2.10", (2,), (1,)),
    )
    assert not evaluate_fixture(replace(fixture, expected_groups=split)).passed
