"""Tests for DashboardState aggregation: per-device totals, the "ai"
(confirmed/evasion) count, a thread-safe snapshot, and resilience to a
corrupt log line (which must not kill the tailer)."""

import json

import pytest

import guard.dashboard_state as ds
from guard.dashboard_state import DashboardState


@pytest.fixture()
def log_path(tmp_path, monkeypatch):
    p = tmp_path / "dns_queries.jsonl"
    p.touch()
    monkeypatch.setattr(ds, "LOG_PATH", p)
    return p


def _entry(ip, blocked=False, severity="clean", mac="aa-bb"):
    return {
        "ts": 1.0,
        "client_ip": ip,
        "client_mac": mac,
        "qname": "example.com",
        "blocked": blocked,
        "reason": "",
        "severity": severity,
    }


def _append(path, entries):
    with path.open("a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_counts_total_blocked_and_ai(log_path):
    state = DashboardState()
    _append(
        log_path,
        [
            _entry("1.1.1.1"),                                  # clean
            _entry("1.1.1.1", blocked=True, severity="suspected"),  # blocked, not ai
            _entry("1.1.1.1", blocked=True, severity="confirmed"),  # blocked + ai
            _entry("1.1.1.1", blocked=True, severity="evasion"),    # blocked + ai
        ],
    )
    state.poll()
    _, stats = state.snapshot()
    s = stats["1.1.1.1"]
    assert s["total"] == 4
    assert s["blocked"] == 3
    assert s["ai"] == 2  # confirmed + evasion only
    assert s["mac"] == "aa-bb"


def test_per_device_separation(log_path):
    state = DashboardState()
    _append(log_path, [_entry("1.1.1.1"), _entry("2.2.2.2", blocked=True, severity="confirmed")])
    state.poll()
    _, stats = state.snapshot()
    assert stats["1.1.1.1"]["total"] == 1 and stats["1.1.1.1"]["ai"] == 0
    assert stats["2.2.2.2"]["ai"] == 1


def test_recent_is_newest_first_and_capped(log_path):
    state = DashboardState(max_recent=3)
    _append(log_path, [_entry(f"10.0.0.{i}") for i in range(5)])
    state.poll()
    recent, _ = state.snapshot()
    assert len(recent) == 3  # capped by max_recent
    assert recent[0]["client_ip"] == "10.0.0.4"  # newest first


def test_only_new_lines_counted_across_polls(log_path):
    state = DashboardState()
    _append(log_path, [_entry("1.1.1.1")])
    state.poll()
    _append(log_path, [_entry("1.1.1.1")])
    state.poll()
    _, stats = state.snapshot()
    assert stats["1.1.1.1"]["total"] == 2  # not 3 - no double counting


def test_corrupt_and_schemaless_lines_skipped(log_path):
    state = DashboardState()
    with log_path.open("a", encoding="utf-8") as f:
        f.write("not json at all\n")
        f.write(json.dumps({"no_client_ip": True}) + "\n")  # valid json, wrong schema
        f.write(json.dumps(_entry("9.9.9.9")) + "\n")
    state.poll()  # must not raise
    _, stats = state.snapshot()
    assert "9.9.9.9" in stats and stats["9.9.9.9"]["total"] == 1


def test_snapshot_returns_copies(log_path):
    state = DashboardState()
    _append(log_path, [_entry("1.1.1.1")])
    state.poll()
    _, stats = state.snapshot()
    stats["1.1.1.1"]["total"] = 999  # mutate the snapshot
    _, stats2 = state.snapshot()
    assert stats2["1.1.1.1"]["total"] == 1  # internal state untouched
