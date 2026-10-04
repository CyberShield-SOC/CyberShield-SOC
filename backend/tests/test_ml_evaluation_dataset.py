"""KK-06: leakage-controlled train / evaluation datasets."""

import json
from dataclasses import replace

import pytest

from app.detection.models import LogRecord
from app.ml.evaluation_dataset import (
    DatasetError,
    SourceBatch,
    build_dataset,
    export_dataset,
    pseudonymize,
    verify_no_leakage,
)
from app.ml.features_source_ip_window import FEATURE_NAMES, extract_window_features

pytestmark = pytest.mark.no_db


def batch(upload, label, hour, ips=("192.0.2.1", "192.0.2.2"), status="SUCCESS", per_ip=2, day=2):
    # line numbers must be unique within an upload (the extractor de-duplicates on upload+line)
    records = [
        LogRecord(
            line_number=index, upload_id=upload, ip_address=ip, username=f"user-{n}", hostname="secret-host",
            timestamp=f"2026-10-{day:02d}T{hour:02d}:00:{n * 10:02d}Z", event_type="login_attempt",
            status=status, message="password=hunter2",
        )
        for index, (ip, n) in enumerate(((ip, n) for ip in ips for n in range(per_ip)), start=1)
    ]
    rows, report = extract_window_features(records)
    assert len(rows) == len(ips), "test helper must yield one row per IP"
    return SourceBatch(upload, label, tuple(rows), report)


@pytest.fixture
def batches():
    return [
        batch("a", "normal", 8),
        batch("b", "suspicious", 9, status="FAILED", per_ip=6),
        batch("c", "normal", 10),
        batch("d", "suspicious", 11, status="FAILED", per_ip=6),
        batch("e", "normal", 12),
    ]


def test_batches_are_never_split_and_eval_is_the_latest(batches):
    ds = build_dataset(batches)
    train_up, eval_up = {r.upload_id for r in ds.train}, {r.upload_id for r in ds.evaluation}
    assert not train_up & eval_up
    assert max(r.window_start for r in ds.train) <= min(r.window_start for r in ds.evaluation)
    assert ds.manifest["leakage_checks"]["train_ends_before_evaluation_starts"] is True


def test_both_behaviors_are_represented_in_each_split(batches):
    ds = build_dataset(batches, eval_fraction=0.3, strict=True)
    for split in ("train", "evaluation"):
        counts = ds.manifest[split]["label_counts"]
        assert counts["normal"] > 0 and counts["suspicious"] > 0, (split, counts)
    assert ds.manifest["warnings"] == []


def test_label_balancing_moves_a_spare_batch_when_the_tail_is_one_sided():
    """Natural temporal tail is all 'normal'; train has two suspicious batches, so one moves over."""

    one_sided = [
        batch("s1", "suspicious", 8, status="FAILED"), batch("s2", "suspicious", 9, status="FAILED"),
        batch("n1", "normal", 10), batch("n2", "normal", 11), batch("n3", "normal", 12),
    ]
    ds = build_dataset(one_sided, eval_fraction=0.3, strict=True)
    assert ds.manifest["evaluation"]["label_counts"]["suspicious"] > 0
    assert ds.manifest["train"]["label_counts"]["suspicious"] > 0      # train keeps its own suspicious batch
    assert ds.manifest["train"]["label_counts"]["normal"] > 0
    # the price of balancing is a time overlap, and it must be reported rather than hidden
    assert ds.manifest["leakage_checks"]["train_ends_before_evaluation_starts"] is False
    assert any("overlap in time" in w for w in ds.manifest["warnings"])


def test_missing_behavior_is_warned_or_rejected_in_strict_mode():
    only_normal_eval = [batch("a", "suspicious", 8, status="FAILED"), batch("b", "normal", 9), batch("c", "normal", 10)]
    ds = build_dataset(only_normal_eval, eval_fraction=0.3)
    assert any("evaluation split has no suspicious" in w for w in ds.manifest["warnings"])
    with pytest.raises(DatasetError):
        build_dataset(only_normal_eval, eval_fraction=0.3, strict=True)


def test_reuploaded_activity_is_removed_and_never_appears_in_both_splits():
    first = batch("first", "normal", 8)
    reupload = batch("reupload", "normal", 8)                        # same IPs, same windows
    later = batch("later", "suspicious", 9, status="FAILED")
    ds = build_dataset([first, reupload, later], eval_fraction=0.5)
    keys = lambda rows: {r.activity_key for r in rows}
    assert not keys(ds.train) & keys(ds.evaluation)
    assert "reupload" not in {r.upload_id for r in ds.train + ds.evaluation}
    removed = ds.manifest["removed_for_leakage_control"]
    assert removed["repeated_activity_rows_removed"] == len(reupload.rows)
    assert ds.manifest["split_policy"]["batches_skipped_empty_or_fully_duplicate"] == 1


def test_duplicate_that_would_cross_the_split_is_counted_and_removed_from_the_later_batch():
    mid = batch("mid", "suspicious", 6, status="FAILED")
    early = batch("early", "normal", 8)
    late = batch("late", "suspicious", 8, status="FAILED", ips=("192.0.2.1", "192.0.2.9"))  # repeats 192.0.2.1@08:00
    ds = build_dataset([mid, early, late], eval_fraction=0.2)
    assert {r.upload_id for r in ds.train} == {"mid", "early"}
    assert [(r.upload_id, r.entity_id) for r in ds.evaluation] == [("late", "192.0.2.9")]
    removed = ds.manifest["removed_for_leakage_control"]
    assert removed == {"repeated_activity_rows_removed": 1, "of_which_would_have_crossed_the_split": 1}


def test_each_activity_window_appears_at_most_once_overall(batches):
    ds = build_dataset(batches + [batch("dupe", "normal", 8)])
    all_keys = [r.activity_key for r in ds.train + ds.evaluation]
    assert len(all_keys) == len(set(all_keys))


def test_verify_no_leakage_fails_loudly(batches):
    ds = build_dataset(batches)
    leaked = replace(ds.evaluation[0], upload_id=ds.train[0].upload_id)
    with pytest.raises(DatasetError, match="both splits"):
        verify_no_leakage(ds.train, [leaked] + ds.evaluation[1:])
    same_activity = replace(ds.evaluation[0], entity_id=ds.train[0].entity_id, window_start=ds.train[0].window_start)
    with pytest.raises(DatasetError, match="activity windows"):
        verify_no_leakage(ds.train, [same_activity])


def test_invalid_inputs_are_rejected(batches):
    with pytest.raises(DatasetError):
        build_dataset(batches[:1])
    with pytest.raises(DatasetError):
        build_dataset([batches[0], replace(batches[1], upload_id="a")])
    with pytest.raises(DatasetError):
        build_dataset([replace(batches[0], label="evil"), batches[1]])
    with pytest.raises(DatasetError):
        build_dataset(batches, eval_fraction=1.5)


def test_manifest_records_counts_coverage_and_limitations(batches):
    m = build_dataset(batches).manifest
    assert m["feature_names"] == list(FEATURE_NAMES) and m["window_seconds"] == 300
    assert m["train"]["rows"] + m["evaluation"]["rows"] == sum(len(b.rows) for b in batches)
    assert set(m["feature_nonzero_fraction"]) == set(FEATURE_NAMES)
    assert m["known_limitations"] and m["source_records"]["total"] > 0
    assert m["feature_nonzero_fraction"]["failed_login_count"] > 0


def test_export_has_no_free_text_or_raw_ips_and_is_reproducible(batches, tmp_path):
    ds = build_dataset(batches)
    paths = export_dataset(ds, tmp_path / "one", salt="test-salt")
    again = export_dataset(ds, tmp_path / "two", salt="test-salt")
    assert [p.read_bytes() for p in paths] == [p.read_bytes() for p in again]

    blob = "".join(p.read_text() for p in paths)
    for secret in ("hunter2", "secret-host", "user-0", "192.0.2.1", "password"):
        assert secret not in blob, secret
    line = json.loads((tmp_path / "one" / "train.jsonl").read_text().splitlines()[0])
    assert set(line) == {"split", "label", "upload_id", "entity", "window_start", "features"}
    assert len(line["features"]) == len(FEATURE_NAMES)

    other_salt = export_dataset(ds, tmp_path / "three", salt="different")[0].read_text()
    assert other_salt != paths[0].read_text()


def test_pseudonymize_requires_salt_and_is_stable():
    assert pseudonymize("192.0.2.1", "s") == pseudonymize("192.0.2.1", "s") != pseudonymize("192.0.2.2", "s")
    with pytest.raises(DatasetError):
        pseudonymize("192.0.2.1", "")
