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
        self._log_lock = threading.Lock()
        self._handle: pydivert.WinDivert | None = None
        LOG_PATH.parent.mkdir(exist_ok=True)

    def _log(self, entry: dict) -> None:
        with self._log_lock:
            with LOG_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def serve_forever(self) -> None:
        self._running = True
        with pydivert.WinDivert(FILTER) as w:
            self._handle = w
            while self._running:
                try:
                    packet = w.recv()
                except OSError:
                    break

                try:
                    request = DNSRecord.parse(bytes(packet.payload))
                    qname = str(request.q.qname)
                except Exception:
                    w.send(packet)
                    continue

                verdict = self.blocklist.classify(qname)
                if not verdict.blocked:
                    w.send(packet)  # let ICS resolve it normally

                self._log(
                    {
                        "ts": time.time(),
                        "client_ip": packet.src_addr,
                        "client_mac": mac_for_ip(packet.src_addr),
                        "qname": qname.rstrip("."),
                        "blocked": verdict.blocked,
                        "reason": verdict.reason,
                    }
                )
        self._handle = None

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._running = False
        if self._handle is not None:
            self._handle.close()
