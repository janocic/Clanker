"""Tests for Nicknames: set/get/clear, length cap, control-char cleaning,
and MAC case-insensitivity, plus persistence across instances."""

from guard.nicknames import MAX_LEN, Nicknames


def test_set_and_get(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    n.set("AA-BB-CC-DD-EE-FF", "Marko laptop")
    assert n.get("AA-BB-CC-DD-EE-FF") == "Marko laptop"


def test_case_insensitive_mac(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    n.set("AA-BB-CC-DD-EE-FF", "Ivan")
    assert n.get("aa-bb-cc-dd-ee-ff") == "Ivan"
    assert n.get("Aa-Bb-Cc-Dd-Ee-Ff") == "Ivan"


def test_empty_nickname_clears(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    n.set("aa-bb-cc-dd-ee-ff", "Temp")
    assert n.get("aa-bb-cc-dd-ee-ff") == "Temp"
    n.set("aa-bb-cc-dd-ee-ff", "")
    assert n.get("aa-bb-cc-dd-ee-ff") == ""
    assert "aa-bb-cc-dd-ee-ff" not in n.all()


def test_length_cap(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    stored = n.set("aa-bb-cc-dd-ee-ff", "x" * (MAX_LEN + 20))
    assert len(stored) == MAX_LEN
    assert len(n.get("aa-bb-cc-dd-ee-ff")) == MAX_LEN


def test_whitespace_collapsed_and_control_chars_dropped(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    stored = n.set("aa-bb-cc-dd-ee-ff", "  Marko\t\n  laptop\x00  ")
    assert stored == "Marko laptop"


def test_empty_mac_is_noop(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    assert n.set("", "whatever") == ""
    assert n.get("") == ""
    assert n.all() == {}


def test_persistence_across_instances(tmp_path):
    path = tmp_path / "n.json"
    Nicknames(path=path).set("AA-BB-CC-DD-EE-FF", "Persist Me")
    # a fresh instance must load the saved (lowercased) name
    assert Nicknames(path=path).get("aa-bb-cc-dd-ee-ff") == "Persist Me"


def test_set_returns_cleaned_value(tmp_path):
    n = Nicknames(path=tmp_path / "n.json")
    assert n.set("aa-bb-cc-dd-ee-ff", "  spaced   out  ") == "spaced out"
