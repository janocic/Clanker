"""Human-friendly nicknames for devices, keyed by MAC address.

Keyed by MAC rather than IP because the IP a device gets can change on
a DHCP renew, while the MAC is the stable identity across a session.
Persisted to config/nicknames.json so names survive a restart.
"""

import json
import threading
from pathlib import Path

NICK_PATH = Path(__file__).resolve().parent.parent / "config" / "nicknames.json"
MAX_LEN = 40


def _clean(nickname: str) -> str:
    # collapse whitespace, drop control chars, cap length
    nickname = "".join(ch for ch in nickname if ch.isprintable())
    return " ".join(nickname.split())[:MAX_LEN].strip()


class Nicknames:
    def __init__(self, path: Path = NICK_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._map: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return {str(k).lower(): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError, AttributeError):
            return {}

    def _save(self) -> None:
        self.path.parent.mkdir(exist_ok=True)
        self.path.write_text(
            json.dumps(self._map, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )

    def get(self, mac: str) -> str:
        if not mac:
            return ""
        with self._lock:
            return self._map.get(mac.lower(), "")

    def all(self) -> dict[str, str]:
        with self._lock:
            return dict(self._map)

    def set(self, mac: str, nickname: str) -> str:
        """Set (or, with an empty nickname, clear) a device's name.
        Returns the cleaned nickname that was stored."""
        mac = (mac or "").lower()
        if not mac:
            return ""
        cleaned = _clean(nickname or "")
        with self._lock:
            if cleaned:
                self._map[mac] = cleaned
            else:
                self._map.pop(mac, None)
            self._save()
        return cleaned
