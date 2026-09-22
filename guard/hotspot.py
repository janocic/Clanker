"""Best-effort helpers around Windows' legacy 'hosted network' WiFi AP
feature, driven entirely through netsh so it is fully scriptable.

Note: many modern WiFi drivers (esp. Intel AX-series) dropped support for
hosted network in favour of the newer Mobile Hotspot (WinRT tethering) API,
which is not easily scriptable from the command line. Run `hotspot-check`
first - if it's unsupported, use Settings > Mobile Hotspot manually and
set that adapter's IPv4 DNS to this machine's own IP by hand.

netsh output language follows the Windows UI language (may be Croatian on
this machine), so the "supported" parsing here is best-effort only -
always read the raw output yourself to confirm.
"""

import subprocess


def _run(cmd: list[str]) -> tuple[int, str, str]:
    # encoding="oem": netsh writes to the console codepage, not the
    # system ANSI codepage text=True would otherwise assume.
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="oem", errors="replace")
    return result.returncode, result.stdout, result.stderr


def check_hosted_network_support() -> dict:
    code, out, err = _run(["netsh", "wlan", "show", "drivers"])
    supported_line = None
    for line in out.splitlines():
        if "hosted network" in line.lower():
            supported_line = line.strip()
            break
    return {"code": code, "raw": out, "err": err, "supported_line": supported_line}


def start_legacy_hotspot(ssid: str, password: str) -> dict:
    configure = _run(
        ["netsh", "wlan", "set", "hostednetwork", "mode=allow", f"ssid={ssid}", f"key={password}"]
    )
    start = _run(["netsh", "wlan", "start", "hostednetwork"])
    return {"configure": configure, "start": start}


def stop_legacy_hotspot() -> tuple[int, str, str]:
    return _run(["netsh", "wlan", "stop", "hostednetwork"])


def status_legacy_hotspot() -> tuple[int, str, str]:
    return _run(["netsh", "wlan", "show", "hostednetwork"])
