"""Loads config/blocklist.yaml and classifies queried hostnames.

Two match tiers, exposed as Verdict.severity:
- "confirmed": exact domain match (curated list or a live-banned domain
  added from the dashboard) - a known LLM/AI provider.
- "suspected": keyword substring match - the hostname mentions something
  AI-adjacent but isn't a listed provider domain. Weaker signal, more
  false-positive prone (see config/blocklist.yaml comments).
"""

import json
import threading
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "blocklist.yaml"
LIVE_PATH = Path(__file__).resolve().parent.parent / "config" / "live_blocklist.json"


@dataclass
class Verdict:
    blocked: bool
    reason: str
    severity: str  # "confirmed" | "suspected" | "clean"


class Blocklist:
    def __init__(self, path: Path = DEFAULT_PATH, live_path: Path = LIVE_PATH):
        self.path = path
        self.live_path = live_path
        self._lock = threading.Lock()
        self.domains: list[str] = []
        self.keywords: list[str] = []
        self.live_domains: list[str] = []
        self.reload()

    def reload(self) -> None:
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        domains = [d.strip().lower() for d in data.get("domains", [])]
        keywords = [k.strip().lower() for k in data.get("keywords", [])]
        live = self._load_live()
        with self._lock:
            self.domains = domains
            self.keywords = keywords
            self.live_domains = live

    def _load_live(self) -> list[str]:
        if not self.live_path.exists():
            return []
        try:
            return json.loads(self.live_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def _save_live(self) -> None:
        self.live_path.parent.mkdir(exist_ok=True)
        self.live_path.write_text(
            json.dumps(sorted(self.live_domains), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def add_live_domain(self, domain: str) -> None:
        domain = domain.strip().lower().rstrip(".")
        with self._lock:
            if domain and domain not in self.live_domains:
                self.live_domains.append(domain)
                self._save_live()

    def remove_live_domain(self, domain: str) -> None:
        domain = domain.strip().lower().rstrip(".")
        with self._lock:
            if domain in self.live_domains:
                self.live_domains.remove(domain)
                self._save_live()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "domains": list(self.domains),
                "keywords": list(self.keywords),
                "live": list(self.live_domains),
            }

    def classify(self, qname: str) -> Verdict:
        name = qname.strip(".").lower()
        with self._lock:
            domains = self.domains
            live_domains = self.live_domains
            keywords = self.keywords

        for domain in live_domains:
            if name == domain or name.endswith("." + domain):
                return Verdict(True, f"live:{domain}", "confirmed")

        for domain in domains:
            if name == domain or name.endswith("." + domain):
                return Verdict(True, f"domain:{domain}", "confirmed")

        for keyword in keywords:
            if keyword in name:
                return Verdict(True, f"keyword:{keyword}", "suspected")

        return Verdict(False, "", "clean")
