"""Tests for the netsh rule-parsing that backs list_blocked(). If this
mis-parses, the dashboard shows the wrong access state and block/unblock
verification wrongly reports failure. Also covers graceful degradation
when netsh hangs (times out) - a hung subprocess must never freeze the
background refresh thread or an API request."""

import subprocess

import guard.access_control as ac
from guard.access_control import RULE_PREFIX, _parse_blocked_ips

# Realistic `netsh advfirewall firewall show rule name=all` excerpt: a couple
# of Windows' own rules (must be ignored), then two of ours. netsh normalizes
# a single remote IP to "<ip>/32" - the mask must be stripped.
SAMPLE = """
Rule Name:                            Core Networking - DNS (UDP-Out)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
RemoteIP:                             Any

Rule Name:                            guard-block-192.168.137.5-in
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Block
RemoteIP:                             192.168.137.5/32

Rule Name:                            guard-block-192.168.137.5-out
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
RemoteIP:                             192.168.137.5/32

Rule Name:                            SomeOtherApp Rule
----------------------------------------------------------------------
RemoteIP:                             10.0.0.9/32

Rule Name:                            guard-block-192.168.137.42-in
----------------------------------------------------------------------
RemoteIP:                             192.168.137.42/32
"""


def test_parses_only_guard_rules_and_strips_mask():
    assert _parse_blocked_ips(SAMPLE) == {"192.168.137.5", "192.168.137.42"}


def test_ignores_non_guard_rules():
    # 10.0.0.9 belongs to a non-guard rule and must not appear.
    assert "10.0.0.9" not in _parse_blocked_ips(SAMPLE)


def test_empty_output():
    assert _parse_blocked_ips("") == set()


def test_plain_ip_without_mask_still_parses():
    text = (
        f"Rule Name:                            {RULE_PREFIX}192.168.137.7-in\n"
        "RemoteIP:                             192.168.137.7\n"
    )
    assert _parse_blocked_ips(text) == {"192.168.137.7"}


def test_remoteip_outside_a_guard_rule_is_ignored():
    text = (
        "Rule Name:                            Unrelated\n"
        "RemoteIP:                             192.168.137.99/32\n"
    )
    assert _parse_blocked_ips(text) == set()


# ---------- graceful degradation when netsh hangs / times out ----------
def _raise_timeout(*args, **kwargs):
    raise subprocess.TimeoutExpired(cmd="netsh", timeout=1)


def _raise_oserror(*args, **kwargs):
    raise OSError("netsh not found")


def test_query_blocked_degrades_to_empty_on_timeout(monkeypatch):
    # A hung `netsh show rule name=all` must not hang or raise - the query
    # yields no rules, and the background refresh keeps its last-good cache.
    monkeypatch.setattr(ac.subprocess, "run", _raise_timeout)
    assert ac._query_blocked() == set()


def test_query_blocked_degrades_to_empty_on_oserror(monkeypatch):
    monkeypatch.setattr(ac.subprocess, "run", _raise_oserror)
    assert ac._query_blocked() == set()


def test_block_and_unblock_do_not_propagate_on_timeout(monkeypatch):
    # A timed-out add/delete-rule call must not raise out of the request
    # handler; it degrades and the caller's verification step reports it.
    monkeypatch.setattr(ac.subprocess, "run", _raise_timeout)
    ac.block_ip("192.168.137.5")  # must not raise
    ac.unblock_ip("192.168.137.5")  # must not raise


def test_refresh_now_degrades_to_empty_on_timeout(monkeypatch):
    monkeypatch.setattr(ac.subprocess, "run", _raise_timeout)
    assert ac.refresh_now() == set()
