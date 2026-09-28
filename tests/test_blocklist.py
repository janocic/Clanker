"""Tests for blocklist.classify - the core correctness surface: an
AI query wrongly cleared is a missed hit; a clean query wrongly flagged
would falsely accuse a player."""

import json

import pytest
import yaml

from guard.blocklist import Blocklist

YAML_DATA = {
    "blocked_tlds": [".ai"],
    "domains": ["openai.com", "chat.openai.com", "claude.ai"],
    "keywords": ["copilot", "midjourney"],
    "doh_providers": ["dns.google", "cloudflare-dns.com"],
}


@pytest.fixture()
def blocklist(tmp_path):
    yaml_path = tmp_path / "blocklist.yaml"
    yaml_path.write_text(yaml.safe_dump(YAML_DATA), encoding="utf-8")
    live_path = tmp_path / "live_blocklist.json"
    live_path.write_text(json.dumps(["banned.example.com"]), encoding="utf-8")
    return Blocklist(path=yaml_path, live_path=live_path)


def test_ai_tld_blocked_confirmed(blocklist):
    v = blocklist.classify("something.ai")
    assert v.blocked and v.severity == "confirmed"
    assert v.reason == "tld:.ai"


def test_ai_tld_matches_subdomain(blocklist):
    assert blocklist.classify("foo.bar.ai").blocked


def test_ai_tld_does_not_over_match(blocklist):
    # A .com host that merely contains "ai" must not hit the .ai TLD rule.
    assert not blocklist.classify("plainsite.com").blocked
    assert not blocklist.classify("aimless.com").blocked


def test_exact_domain_confirmed(blocklist):
    v = blocklist.classify("openai.com")
    assert v.blocked and v.severity == "confirmed"
    assert v.reason == "domain:openai.com"


def test_subdomain_of_listed_domain(blocklist):
    v = blocklist.classify("api.openai.com")
    assert v.blocked and v.severity == "confirmed"
    assert v.reason == "domain:openai.com"


def test_domain_boundary_not_substring(blocklist):
    # "notopenai.com" must NOT match "openai.com" (suffix must be on a label
    # boundary), and it contains no keyword either -> clean.
    assert not blocklist.classify("notopenai.com").blocked


def test_doh_provider_is_evasion(blocklist):
    v = blocklist.classify("dns.google")
    assert v.blocked and v.severity == "evasion"
    assert v.reason == "doh:dns.google"


def test_doh_subdomain_is_evasion(blocklist):
    assert blocklist.classify("mozilla.cloudflare-dns.com").severity == "evasion"


def test_keyword_is_suspected(blocklist):
    v = blocklist.classify("mycopilot.example.net")
    assert v.blocked and v.severity == "suspected"
    assert v.reason == "keyword:copilot"


def test_clean_query(blocklist):
    v = blocklist.classify("example.com")
    assert not v.blocked and v.severity == "clean" and v.reason == ""


def test_trailing_dot_and_case_normalized(blocklist):
    # FQDN form (trailing dot) and mixed case must classify the same.
    assert blocklist.classify("OpenAI.COM.").reason == "domain:openai.com"


def test_evasion_takes_priority_over_keyword():
    # A DoH host that ALSO contains a keyword must be reported as the
    # stronger "evasion", proving DoH is checked before the keyword tier.
    # (This host literally contains the "copilot" keyword substring.)
    data = {
        "blocked_tlds": [],
        "domains": [],
        "keywords": ["copilot"],
        "doh_providers": ["copilot-doh.example.net"],
    }
    v = _bl(data, []).classify("copilot-doh.example.net")
    assert v.severity == "evasion"
    assert v.reason == "doh:copilot-doh.example.net"
    # Sanity: the same host is only a weak "suspected" keyword hit when it is
    # NOT a DoH provider - so the assertion above really tests the ordering.
    data2 = dict(data, doh_providers=[])
    assert _bl(data2, []).classify("copilot-doh.example.net").severity == "suspected"


def test_live_domain_add_and_remove(blocklist):
    assert blocklist.classify("banned.example.com").reason == "live:banned.example.com"
    # add a new one at runtime
    blocklist.add_live_domain("Evil.Example.ORG")
    v = blocklist.classify("sub.evil.example.org")
    assert v.blocked and v.severity == "confirmed" and v.reason == "live:evil.example.org"
    # remove it again
    blocklist.remove_live_domain("evil.example.org")
    assert not blocklist.classify("sub.evil.example.org").blocked


def test_add_live_domain_persists(tmp_path):
    yaml_path = tmp_path / "blocklist.yaml"
    yaml_path.write_text(yaml.safe_dump(YAML_DATA), encoding="utf-8")
    live_path = tmp_path / "live_blocklist.json"
    bl = Blocklist(path=yaml_path, live_path=live_path)
    bl.add_live_domain("persisted.example")
    saved = json.loads(live_path.read_text(encoding="utf-8"))
    assert "persisted.example" in saved


def test_add_live_domain_does_not_mutate_in_place(blocklist):
    # Regression guard for the classify() data race: publishing a new live
    # domain must replace the list object, not mutate the one classify may
    # be iterating.
    before = blocklist.live_domains
    blocklist.add_live_domain("another.example")
    assert blocklist.live_domains is not before


def test_remove_live_domain_does_not_mutate_in_place(blocklist):
    # Same copy-on-write guard for removal: classify() may hold a reference
    # to the pre-removal list, so removal must swap in a new list rather
    # than mutate the old one in place (which could raise mid-iteration).
    before = blocklist.live_domains
    assert "banned.example.com" in before
    blocklist.remove_live_domain("banned.example.com")
    assert blocklist.live_domains is not before
    assert before == ["banned.example.com"]  # old snapshot untouched
    assert "banned.example.com" not in blocklist.live_domains


def _bl(data, live):
    import tempfile

    d = tempfile.mkdtemp()
    yp = f"{d}/b.yaml"
    lp = f"{d}/l.json"
    from pathlib import Path

    Path(yp).write_text(yaml.safe_dump(data), encoding="utf-8")
    Path(lp).write_text(json.dumps(live), encoding="utf-8")
    return Blocklist(path=Path(yp), live_path=Path(lp))
