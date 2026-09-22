"""Maps IPs to MAC addresses via the Windows ARP table (arp -a)."""

import re
import subprocess
import time

_CACHE_TTL_SECONDS = 2.0
_cache = {"ts": 0.0, "table": {}}

_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
)
_IGNORED_MACS = {"ff-ff-ff-ff-ff-ff"}


def get_arp_table(force: bool = False) -> dict[str, str]:
    now = time.time()
    if not force and now - _cache["ts"] < _CACHE_TTL_SECONDS:
        return _cache["table"]

    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=3
        ).stdout
    except Exception:
        return _cache["table"]

    table: dict[str, str] = {}
    for line in out.splitlines():
        match = _ARP_LINE.search(line)
        if not match:
            continue
        ip, mac = match.group(1), match.group(2).lower()
        if mac in _IGNORED_MACS or mac.startswith("01-00-5e"):
            continue
        table[ip] = mac

    _cache["ts"] = now
    _cache["table"] = table
    return table


def mac_for_ip(ip: str) -> str:
    return get_arp_table().get(ip, "?")
