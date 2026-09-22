"""Minimal forwarding DNS proxy that sinkholes AI-related domains.

Every client is expected to be handed this proxy's IP as their DNS server
(via the hotspot's DHCP). Non-blocked queries are forwarded upstream
unchanged; blocked queries get NXDOMAIN. Every query is logged as JSON
lines for the dashboard to tail.
"""

import json
import socket
import threading
import time
from pathlib import Path

from dnslib import DNSRecord, RCODE

from .blocklist import Blocklist
from .devices import mac_for_ip

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "dns_queries.jsonl"


class DNSProxy:
    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        port: int = 53,
        upstream: str = "1.1.1.1",
        upstream_port: int = 53,
        blocklist: Blocklist | None = None,
    ):
        self.bind_ip = bind_ip
        self.port = port
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.blocklist = blocklist or Blocklist()
        self._sock: socket.socket | None = None
        self._running = False
        self._log_lock = threading.Lock()
        LOG_PATH.parent.mkdir(exist_ok=True)

    def _log(self, entry: dict) -> None:
        with self._log_lock:
            with LOG_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        client_ip = addr[0]
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return

        qname = str(request.q.qname)
        verdict = self.blocklist.classify(qname)

        if verdict.blocked:
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            response = reply.pack()
        else:
            try:
                response = request.send(self.upstream, self.upstream_port, timeout=3)
            except Exception:
                reply = request.reply()
                reply.header.rcode = RCODE.SERVFAIL
                response = reply.pack()

        try:
            self._sock.sendto(response, addr)
        except OSError:
            pass

        self._log(
            {
                "ts": time.time(),
                "client_ip": client_ip,
                "client_mac": mac_for_ip(client_ip),
                "qname": qname.rstrip("."),
                "blocked": verdict.blocked,
                "reason": verdict.reason,
            }
        )

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.bind_ip, self.port))
        self._running = True
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                break
            threading.Thread(target=self._handle, args=(data, addr), daemon=True).start()

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
