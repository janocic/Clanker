"""EXPERIMENTAL (phase 2): SNI-based traffic visibility using WinDivert.

DNS-level blocking alone is trivially bypassed by pointing a device at a
public DNS server or using DNS-over-HTTPS. This module intercepts TCP
packets to port 443 at the network layer, extracts the SNI (server name)
from the TLS ClientHello - which is sent in cleartext even over an
otherwise-encrypted connection - and logs/tallies traffic per source IP
regardless of which DNS resolver the client used.

Requires: pip install pydivert (bundles the WinDivert driver on Windows),
and an Administrator shell. Not yet wired into the main dashboard - run
standalone with `python -m guard.traffic_monitor` for now.
"""

import json
import struct
import time
from pathlib import Path

try:
    import pydivert
except ImportError:
    pydivert = None

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "traffic.jsonl"


def extract_sni(tcp_payload: bytes) -> str | None:
    """Parse a TLS ClientHello and return the SNI hostname, if present."""
    try:
        if len(tcp_payload) < 6 or tcp_payload[0] != 0x16:
            return None  # not a TLS handshake record

        handshake = tcp_payload[5:]
        if len(handshake) < 4 or handshake[0] != 0x01:
            return None  # not a ClientHello

        pos = 4  # skip handshake msg header (type + 3-byte length)
        pos += 2  # client_version
        pos += 32  # random
        if pos >= len(handshake):
            return None

        session_id_len = handshake[pos]
        pos += 1 + session_id_len

        cipher_suites_len = struct.unpack(">H", handshake[pos : pos + 2])[0]
        pos += 2 + cipher_suites_len

        compression_len = handshake[pos]
        pos += 1 + compression_len

        if pos + 2 > len(handshake):
            return None
        ext_total_len = struct.unpack(">H", handshake[pos : pos + 2])[0]
        pos += 2
        end = min(pos + ext_total_len, len(handshake))

        while pos + 4 <= end:
            ext_type = struct.unpack(">H", handshake[pos : pos + 2])[0]
            ext_len = struct.unpack(">H", handshake[pos + 2 : pos + 4])[0]
            ext_data = handshake[pos + 4 : pos + 4 + ext_len]
            if ext_type == 0x00 and len(ext_data) >= 5:  # server_name extension
                name_len = struct.unpack(">H", ext_data[3:5])[0]
                return ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")
            pos += 4 + ext_len
        return None
    except Exception:
        return None


def run(filter_str: str = "tcp.DstPort == 443") -> None:
    if pydivert is None:
        raise RuntimeError(
            "pydivert nije instaliran. `pip install pydivert` i pokreni ovo kao Administrator."
        )

    LOG_PATH.parent.mkdir(exist_ok=True)
    byte_counters: dict[str, int] = {}

    with pydivert.WinDivert(filter_str) as w, LOG_PATH.open("a", encoding="utf-8") as logf:
        print(f"[traffic_monitor] presrecem: {filter_str} (Ctrl+C za izlaz)")
        for packet in w:
            byte_counters[packet.src_addr] = byte_counters.get(packet.src_addr, 0) + len(
                packet.raw.tobytes()
            )

            if packet.tcp and packet.payload:
                sni = extract_sni(bytes(packet.payload))
                if sni:
                    entry = {
                        "ts": time.time(),
                        "src": packet.src_addr,
                        "dst": packet.dst_addr,
                        "sni": sni,
                    }
                    logf.write(json.dumps(entry) + "\n")
                    logf.flush()

            w.send(packet)


if __name__ == "__main__":
    run()
