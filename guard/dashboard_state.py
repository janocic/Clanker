"""Shared, continuously-updated view of logs/dns_queries.jsonl.

A single instance is created once in main.py and handed to both the Rich
terminal dashboard and the Flask API, so both read the same data instead
of each tailing the log file independently.
"""

import json
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "dns_queries.jsonl"


class DashboardState:
    def __init__(self, max_recent: int = 50):
        self.recent = deque(maxlen=max_recent)
        self.stats = defaultdict(lambda: {"total": 0, "blocked": 0, "mac": "?"})
        self._lock = threading.Lock()
        LOG_PATH.parent.mkdir(exist_ok=True)
        LOG_PATH.touch(exist_ok=True)
        with LOG_PATH.open("r", encoding="utf-8") as f:
            f.seek(0, 2)
            self._pos = f.tell()

    def poll(self) -> None:
        with LOG_PATH.open("r", encoding="utf-8") as f:
            f.seek(self._pos)
            lines = f.readlines()
            self._pos = f.tell()

        if not lines:
            return

        with self._lock:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.recent.appendleft(entry)
                stat = self.stats[entry["client_ip"]]
                stat["total"] += 1
                stat["mac"] = entry.get("client_mac", "?")
                if entry.get("blocked"):
                    stat["blocked"] += 1

    def snapshot(self) -> tuple[list[dict], dict[str, dict]]:
        with self._lock:
            return list(self.recent), {ip: dict(s) for ip, s in self.stats.items()}

    def run_forever(self, interval: float = 0.5) -> None:
        while True:
            self.poll()
            time.sleep(interval)

    def start_background(self, interval: float = 0.5) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, args=(interval,), daemon=True)
        t.start()
        return t
