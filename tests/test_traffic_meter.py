"""Tests for compute_suspicious - the leave-one-out bandwidth heuristic
that flags a device as "look closer". A wrong flag risks falsely accusing
a player, so the boundaries matter."""

from guard.traffic_meter import (
    SUSPICIOUS_FLOOR_BPS,
    SUSPICIOUS_MULTIPLIER,
    _median,
    compute_suspicious,
)


def test_all_zero_none_flagged():
    assert compute_suspicious({"a": 0.0, "b": 0.0, "c": 0.0}) == {
        "a": False,
        "b": False,
        "c": False,
    }


def test_empty_input():
    assert compute_suspicious({}) == {}


def test_two_devices_only_the_outlier_flagged():
    # Leave-one-out: the big device is compared against just the small one
    # (so it stands out), and the small device against just the big one
    # (so it does not). Including the outlier in its own comparison group
    # would hide it.
    result = compute_suspicious({"big": 5_000_000.0, "small": 1_000.0})
    assert result == {"big": True, "small": False}


def test_single_active_device_uses_absolute_floor():
    # No peer to compare against -> stricter absolute floor (FLOOR * 2).
    assert compute_suspicious({"solo": SUSPICIOUS_FLOOR_BPS * 2 + 1}) == {"solo": True}
    assert compute_suspicious({"solo": SUSPICIOUS_FLOOR_BPS * 2 - 1}) == {"solo": False}


def test_floor_dominates_when_peers_are_tiny():
    # Peers are near-zero so median*multiplier is tiny; the absolute floor
    # must still gate, i.e. a modest device is not flagged just for being
    # 2.5x above near-idle peers.
    rates = {"x": SUSPICIOUS_FLOOR_BPS - 1, "y": 10.0, "z": 20.0}
    assert compute_suspicious(rates)["x"] is False
    rates2 = {"x": SUSPICIOUS_FLOOR_BPS + 1, "y": 10.0, "z": 20.0}
    assert compute_suspicious(rates2)["x"] is True


def test_multiplier_gate_above_floor():
    # All peers are well above the floor, so the median*multiplier gate is
    # what matters. Peers ~200k => threshold = 200k * 2.5 = 500k.
    peers = 200_000.0
    threshold = peers * SUSPICIOUS_MULTIPLIER
    rates = {"hog": threshold + 1, "a": peers, "b": peers, "c": peers}
    assert compute_suspicious(rates)["hog"] is True
    rates_below = {"hog": threshold - 1, "a": peers, "b": peers, "c": peers}
    assert compute_suspicious(rates_below)["hog"] is False


def test_zero_rate_device_never_flagged_even_with_peers():
    result = compute_suspicious({"idle": 0.0, "busy": 10_000_000.0})
    assert result["idle"] is False


def test_median_odd_and_even():
    assert _median([1.0, 2.0, 3.0]) == 2.0
    assert _median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert _median([7.0]) == 7.0
