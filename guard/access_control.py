"""Cuts a client's network access via Windows Firewall rules.

Windows doesn't expose a way to force a real WiFi disassociation for a
Mobile Hotspot client, so this is a network-level cutoff instead: the
device stays associated to the WiFi but every packet to/from its IP is
dropped by the firewall. Equivalent in effect for keeping someone off
the internet during a competition.
"""

import subprocess

RULE_PREFIX = "guard-block-"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    # encoding="oem": netsh writes to the console codepage, not the
    # system ANSI codepage: text=True alone picks the latter and can
    # crash on non-ASCII rule names/descriptions already present in
    # Windows' own default firewall rules (name=all lists everything).
    return subprocess.run(cmd, capture_output=True, text=True, encoding="oem", errors="replace")


def _rule_names(ip: str) -> tuple[str, str]:
    base = f"{RULE_PREFIX}{ip}"
    return f"{base}-in", f"{base}-out"


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


def list_blocked() -> set[str]:
    out = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]).stdout
    blocked: set[str] = set()
    current_is_ours = False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Rule Name:"):
            current_is_ours = line.split(":", 1)[1].strip().startswith(RULE_PREFIX)
        elif current_is_ours and line.startswith("RemoteIP:"):
            blocked.add(line.split(":", 1)[1].strip())
    return blocked
