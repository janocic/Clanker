"""Cuts a client's network access via Windows Firewall rules.

Windows doesn't expose a way to force a real WiFi disassociation for a
Mobile Hotspot client, so this is a network-level cutoff instead: the
device stays associated to the WiFi but every packet to/from its IP is
dropped by the firewall. Equivalent in effect for keeping someone off
the internet during a competition.
"""

import subprocess
import threading
import time

RULE_PREFIX = "guard-block-"

# `netsh advfirewall firewall show rule name=all` lists every firewall
# rule on the system (often hundreds, including Windows' own defaults)
# and can take several seconds. list_blocked() is polled on every
# dashboard render/API request (a couple of times a second), so the
# actual netsh call runs on a background timer instead - callers just
# read the last cached result and never block on it.
_REFRESH_INTERVAL_SECONDS = 3.0
_lock = threading.Lock()
_cache: set[str] = set()
_started = False


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    # encoding="oem": netsh writes to the console codepage, not the
    # system ANSI codepage: text=True alone picks the latter and can
    # crash on non-ASCII rule names/descriptions already present in
    # Windows' own default firewall rules (name=all lists everything).
    return subprocess.run(cmd, capture_output=True, text=True, encoding="oem", errors="replace")


def _rule_names(ip: str) -> tuple[str, str]:
    base = f"{RULE_PREFIX}{ip}"
    return f"{base}-in", f"{base}-out"


def _query_blocked() -> set[str]:
    out = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]).stdout
    blocked: set[str] = set()
    current_is_ours = False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Rule Name:"):
            current_is_ours = line.split(":", 1)[1].strip().startswith(RULE_PREFIX)
        elif current_is_ours and line.startswith("RemoteIP:"):
            # netsh normalizes a single IP to CIDR form, e.g.
            # "192.168.5.254/32" - strip the mask so it matches the plain
            # IP used everywhere else (otherwise every block/unblock check
            # fails and the rule looks "not applied" even when it was).
            blocked.add(line.split(":", 1)[1].strip().split("/")[0])
    return blocked


def refresh_now() -> set[str]:
    """Synchronous refresh. Only call this from a user-triggered action
    (block/unblock), never from a polling loop - it shells out."""
    blocked = _query_blocked()
    with _lock:
        _cache.clear()
        _cache.update(blocked)
    return blocked


def _refresh_loop() -> None:
    while True:
        time.sleep(_REFRESH_INTERVAL_SECONDS)
        try:
            refresh_now()
        except Exception:
            pass  # keep serving the last known-good cache


def _ensure_background_refresh_started() -> None:
    global _started
    if _started:
        return
    with _lock:
        if _started:
            return
        _started = True
    refresh_now()  # prime the cache so the first read isn't empty
    threading.Thread(target=_refresh_loop, daemon=True).start()


def block_ip(ip: str) -> None:
    name_in, name_out = _rule_names(ip)
    _run(
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name_in}", "dir=in", "action=block", f"remoteip={ip}",
        ]
    )
    _run(
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name_out}", "dir=out", "action=block", f"remoteip={ip}",
        ]
    )


def unblock_ip(ip: str) -> None:
    name_in, name_out = _rule_names(ip)
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name_in}"])
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name_out}"])


def _guard_rule_names() -> set[str]:
    out = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]).stdout
    names: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Rule Name:"):
            name = line.split(":", 1)[1].strip()
            if name.startswith(RULE_PREFIX):
                names.add(name)
    return names


def unblock_all() -> int:
    """Remove every guard-block firewall rule (a clean slate). Returns
    how many distinct rule names were deleted. Needs Administrator."""
    names = _guard_rule_names()
    for name in names:
        # delete by name removes all rules sharing that name, incl. dupes
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    refresh_now()
    return len(names)


def list_blocked() -> set[str]:
    """Fast, non-blocking read of the last background-refreshed result.
    Use refresh_now() instead right after block_ip/unblock_ip, where you
    need an up-to-date answer immediately."""
    _ensure_background_refresh_started()
    with _lock:
        return set(_cache)
