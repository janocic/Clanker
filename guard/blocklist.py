"""Loads config/blocklist.yaml and classifies queried hostnames."""

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "blocklist.yaml"


@dataclass
class Verdict:
    blocked: bool
    reason: str


class Blocklist:
    def __init__(self, path: Path = DEFAULT_PATH):
        self.path = path
        self.domains: list[str] = []
        self.keywords: list[str] = []
        self.reload()

    def reload(self) -> None:
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        self.domains = [d.strip().lower() for d in data.get("domains", [])]
        self.keywords = [k.strip().lower() for k in data.get("keywords", [])]

    def classify(self, qname: str) -> Verdict:
        name = qname.strip(".").lower()

        for domain in self.domains:
            if name == domain or name.endswith("." + domain):
                return Verdict(True, f"domain:{domain}")

        for keyword in self.keywords:
            if keyword in name:
                return Verdict(True, f"keyword:{keyword}")

        return Verdict(False, "")
