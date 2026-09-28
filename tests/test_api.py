"""Tests for api.py input handling: domain normalization, IP/MAC
validation, and that the endpoints reject bad input before doing any work
(a malformed IP must never reach the firewall shell-out)."""

import json

import pytest
import yaml

import guard.dashboard_state as ds
from guard.api import _normalize_domain, _valid_ip, create_app
from guard.blocklist import Blocklist
from guard.dashboard_state import DashboardState
from guard.nicknames import Nicknames


# ---------- pure helpers ----------
def test_normalize_domain_basic():
    assert _normalize_domain("OpenAI.com") == "openai.com"


def test_normalize_domain_strips_scheme_path_port():
    assert _normalize_domain("https://chat.openai.com/foo/bar") == "chat.openai.com"
    assert _normalize_domain("http://example.com:8080") == "example.com"


def test_normalize_domain_rejects_single_label():
    assert _normalize_domain("localhost") is None
    assert _normalize_domain("ai") is None


def test_normalize_domain_rejects_garbage():
    assert _normalize_domain("") is None
    assert _normalize_domain("   ") is None
    assert _normalize_domain("has space.com") is None
    assert _normalize_domain("-bad.com") is None


def test_normalize_domain_accepts_multi_label():
    assert _normalize_domain("a.b.c.example.co.uk") == "a.b.c.example.co.uk"


def test_valid_ip():
    assert _valid_ip("192.168.137.5")
    assert _valid_ip("10.0.0.1")


def test_invalid_ip():
    assert not _valid_ip("999.1.1.1")
    assert not _valid_ip("not-an-ip")
    assert not _valid_ip("192.168.1")
    assert not _valid_ip("::1")  # IPv6 is not accepted by the IPv4 check
    assert not _valid_ip("")


# ---------- endpoints via test_client ----------
@pytest.fixture()
def client(tmp_path, monkeypatch):
    log = tmp_path / "dns.jsonl"
    log.touch()
    monkeypatch.setattr(ds, "LOG_PATH", log)
    state = DashboardState()

    yaml_path = tmp_path / "b.yaml"
    yaml_path.write_text(yaml.safe_dump({"domains": ["openai.com"], "keywords": [], "doh_providers": [], "blocked_tlds": [".ai"]}), encoding="utf-8")
    live = tmp_path / "live.json"
    live.write_text("[]", encoding="utf-8")
    blocklist = Blocklist(path=yaml_path, live_path=live)

    nicks = Nicknames(path=tmp_path / "n.json")
    app = create_app(state, blocklist, traffic_meter=None, nicknames=nicks)
    app.testing = True
    return app.test_client(), blocklist


def _post(c, path, body):
    return c.post(path, data=json.dumps(body), content_type="application/json")


def test_nickname_rejects_bad_mac(client):
    c, _ = client
    r = _post(c, "/api/nickname", {"mac": "not-a-mac", "nickname": "x"})
    assert r.status_code == 400


def test_nickname_accepts_good_mac_and_lowercases(client):
    c, _ = client
    r = _post(c, "/api/nickname", {"mac": "AA:BB:CC:DD:EE:FF", "nickname": "Laptop"})
    assert r.status_code == 200
    assert r.get_json()["mac"] == "aa:bb:cc:dd:ee:ff"
    assert r.get_json()["nickname"] == "Laptop"


def test_block_rejects_invalid_ip_without_shellout(client, monkeypatch):
    c, _ = client
    import guard.access_control as ac

    def _boom(*a, **k):  # must never be reached for an invalid IP
        raise AssertionError("access_control was called with an invalid IP")

    monkeypatch.setattr(ac, "block_ip", _boom)
    monkeypatch.setattr(ac, "refresh_now", _boom)
    r = _post(c, "/api/block", {"ip": "not-an-ip"})
    assert r.status_code == 400


def test_unblock_rejects_invalid_ip(client):
    c, _ = client
    r = _post(c, "/api/unblock", {"ip": "999.999.999.999"})
    assert r.status_code == 400


def test_blocklist_add_rejects_bad_domain(client):
    c, _ = client
    r = _post(c, "/api/blocklist", {"domain": "!!!"})
    assert r.status_code == 400


def test_blocklist_add_normalizes_and_adds(client):
    c, blocklist = client
    r = _post(c, "/api/blocklist", {"domain": "https://Evil.Example.com/path"})
    assert r.status_code == 200
    assert r.get_json()["domain"] == "evil.example.com"
    assert "evil.example.com" in blocklist.snapshot()["live"]


def test_missing_body_is_handled(client):
    c, _ = client
    # No JSON body at all must not 500.
    r = c.post("/api/block")
    assert r.status_code == 400


# ---------- /api/health (DNS-filter liveness the operator sees) ----------
class _StubBlocker:
    def __init__(self, up):
        self._up = up

    def is_running(self):
        return self._up


def _health_client(tmp_path, monkeypatch, blocker):
    log = tmp_path / "dns.jsonl"
    log.touch()
    monkeypatch.setattr(ds, "LOG_PATH", log)
    state = DashboardState()
    yaml_path = tmp_path / "b.yaml"
    yaml_path.write_text(
        yaml.safe_dump({"domains": [], "keywords": [], "doh_providers": [], "blocked_tlds": []}),
        encoding="utf-8",
    )
    live = tmp_path / "live.json"
    live.write_text("[]", encoding="utf-8")
    app = create_app(state, Blocklist(path=yaml_path, live_path=live), blocker=blocker)
    app.testing = True
    return app.test_client()


def test_health_reports_blocker_up(tmp_path, monkeypatch):
    c = _health_client(tmp_path, monkeypatch, _StubBlocker(True))
    assert c.get("/api/health").get_json() == {"blockerUp": True}


def test_health_reports_blocker_down(tmp_path, monkeypatch):
    c = _health_client(tmp_path, monkeypatch, _StubBlocker(False))
    assert c.get("/api/health").get_json() == {"blockerUp": False}


def test_health_defaults_up_when_no_blocker_wired(client):
    # No blocker passed to create_app -> report up rather than false-alarm.
    c, _ = client
    assert c.get("/api/health").get_json() == {"blockerUp": True}
