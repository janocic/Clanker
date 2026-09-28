"""Tests for DNSBlocker.decide - the pure per-packet decision (no WinDivert
calls). The blocker loop must never die on one query: a classify() error has
to fail open (re-inject + continue) rather than propagate and take down all
DNS filtering for the rest of the event."""

import guard.dns_blocker as dns_blocker
from guard.blocklist import Verdict
from guard.dns_blocker import DNSBlocker


class _RaisingBlocklist:
    def classify(self, qname):
        raise RuntimeError("classify blew up")


class _StubBlocklist:
    def __init__(self, verdict):
        self._verdict = verdict

    def classify(self, qname):
        return self._verdict


def test_decide_fails_open_when_classify_raises():
    blocker = DNSBlocker(blocklist=_RaisingBlocklist())
    reinject, entry = blocker.decide("evil.example.com", "192.168.137.5")
    assert reinject is True  # re-inject: let it through, keep serving
    assert entry is None     # nothing logged for the errored query


def test_decide_allows_clean_query(monkeypatch):
    monkeypatch.setattr(dns_blocker, "mac_for_ip", lambda ip: "aa-bb-cc")
    blocker = DNSBlocker(blocklist=_StubBlocklist(Verdict(False, "", "clean")))
    reinject, entry = blocker.decide("example.com", "192.168.137.5")
    assert reinject is True
    assert entry is not None
    assert entry["blocked"] is False
    assert entry["client_ip"] == "192.168.137.5"
    assert entry["client_mac"] == "aa-bb-cc"


def test_decide_drops_blocked_query(monkeypatch):
    monkeypatch.setattr(dns_blocker, "mac_for_ip", lambda ip: "aa-bb-cc")
    blocker = DNSBlocker(
        blocklist=_StubBlocklist(Verdict(True, "domain:openai.com", "confirmed"))
    )
    reinject, entry = blocker.decide("openai.com.", "192.168.137.9")
    assert reinject is False  # blocked -> do NOT re-inject (client times out)
    assert entry["blocked"] is True
    assert entry["qname"] == "openai.com"  # trailing dot stripped in the log
    assert entry["severity"] == "confirmed"
