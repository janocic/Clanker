"""DNS-query blocker that works alongside Windows ICS / Mobile Hotspot.

Windows' Internet Connection Sharing (which is what Mobile Hotspot runs
on top of) binds its own DNS proxy on 0.0.0.0:53, system-wide, whenever
the hotspot is on. A normal socket-based DNS server on this machine can
never bind port 53 next to it (WinError 10048: only one usage of each
socket address is normally permitted).

Instead of competing for the socket, this intercepts DNS query packets
at the network layer with WinDivert *before* they reach ICS's own
listener: queries matching the blocklist are dropped (the client sees a
timeout, not an instant NXDOMAIN - a deliberate simplification for the
MVP); everything else is re-injected untouched and ICS resolves it
exactly as if this tool weren't running at all.

Requires: pydivert (bundles the WinDivert driver) and an Administrator
shell to load the driver.
"""

import json
import threading
import time
from pathlib import Path

import pydivert
from dnslib import DNSRecord

from .blocklist import Blocklist
from .devices import mac_for_ip

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "dns_queries.jsonl"
FILTER = "inbound and udp.DstPort == 53"


class DNSBlocker:
    def __init__(self, blocklist: Blocklist | None = None):
        self.blocklist = blocklist or Blocklist()
        self._running = False
        # True only while the capture loop is actively intercepting udp/53.
        # Lets the operator be warned if filtering stops mid-event.
        self._healthy = False
        self._log_lock = threading.Lock()
        self._handle: pydivert.WinDivert | None = None
        LOG_PATH.parent.mkdir(exist_ok=True)

    def _log(self, entry: dict) -> None:
        with self._log_lock:
            with LOG_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def is_running(self) -> bool:
        """True only while the filter loop is actively intercepting udp/53.
        Goes False if the loop exits unexpectedly (e.g. a driver error), so
        the operator can be warned that DNS filtering stopped mid-event."""
        return self._healthy

    def decide(self, qname: str, src_addr: str) -> tuple[bool, dict | None]:
        """Pure per-packet decision (no WinDivert calls): classify the query
        and build its log entry. Returns (reinject, log_entry).

        Isolated from the socket loop so it can be unit-tested without the
        driver. On any classify error it fails open - returns (True, None) -
        so the packet is re-injected and the loop keeps serving instead of
        the whole blocker dying on one query.
        """
        try:
            verdict = self.blocklist.classify(qname)
        except Exception:
            return True, None  # fail open: let it through, keep serving
        entry = {
            "ts": time.time(),
            "client_ip": src_addr,
            "client_mac": mac_for_ip(src_addr),
            "qname": qname.rstrip("."),
            "blocked": verdict.blocked,
            "reason": verdict.reason,
            "severity": verdict.severity,
        }
        return (not verdict.blocked), entry

    def serve_forever(self) -> None:
        self._running = True
        try:
            with pydivert.WinDivert(FILTER) as w:
                self._handle = w
                self._healthy = True
                while self._running:
                    try:
                        packet = w.recv()
                    except OSError:
                        if not self._running:
                            break  # intentional shutdown: stop() closed the handle
                        # Unexpected: the handle died under us. Stop cleanly
                        # and stay unhealthy so the operator is warned that
                        # filtering stopped, rather than tight-looping on a
                        # dead handle.
                        self._running = False
                        break

                    try:
                        request = DNSRecord.parse(bytes(packet.payload))
                        qname = str(request.q.qname)
                    except Exception:
                        w.send(packet)
                        continue

                    reinject, entry = self.decide(qname, packet.src_addr)
                    if reinject:
                        w.send(packet)  # let ICS resolve it normally
                    if entry is not None:
                        # Logging must never take the blocker down - a full
                        # disk or ARP hiccup should lose a line, not stop it.
                        try:
                            self._log(entry)
                        except Exception:
                            pass
        finally:
            # Whether we exited on shutdown or a driver error, filtering is no
            # longer running - reflect that so the dashboard can show it.
            self._healthy = False
            self._handle = None

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._running = False
        if self._handle is not None:
            self._handle.close()
