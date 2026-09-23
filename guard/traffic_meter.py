"""Per-device bandwidth meter, feeding the dashboard's traffic sparkline
and the "unusually high traffic" flag.

Scoped to the default Windows Mobile Hotspot / ICS client subnet
(192.168.137.0/24) via the WinDivert filter itself, so it only counts
hotspot clients and not the host's own primary internet connection.
Adjust HOTSPOT_SUBNET_PREFIX if your hotspot uses a different range.

Bandwidth alone is a weak AI-usage signal - a video call, a Windows
update or a big download all look the same on the wire. Treat
"suspicious" as "look closer", never as proof.
"""

import threading
import time
from collections import defaultdict, deque

import pydivert

HOTSPOT_SUBNET_PREFIX = "192.168.137"
GATEWAY_IP = f"{HOTSPOT_SUBNET_PREFIX}.1"
_LOW = f"{HOTSPOT_SUBNET_PREFIX}.1"
_HIGH = f"{HOTSPOT_SUBNET_PREFIX}.254"

# Match a packet if EITHER endpoint is a hotspot client - i.e. both the
# client's upload (SrcAddr in range) and its download (DstAddr in range).
# The old filter was "inbound and SrcAddr in range", which only counted
# upload and missed all the download, so total traffic looked far too
# small to be useful.
FILTER = (
    f"(ip.SrcAddr >= {_LOW} and ip.SrcAddr <= {_HIGH}) or "
    f"(ip.DstAddr >= {_LOW} and ip.DstAddr <= {_HIGH})"
)

SAMPLE_INTERVAL_SECONDS = 2.0
HISTORY_LENGTH = 30  # 30 samples * 2s = last 60s

SUSPICIOUS_FLOOR_BPS = 150_000  # ~1.2 Mbit/s sustained
SUSPICIOUS_MULTIPLIER = 2.5  # vs. median of other active devices


class TrafficMeter:
    def __init__(
        self,
        sample_interval: float = SAMPLE_INTERVAL_SECONDS,
        history_length: int = HISTORY_LENGTH,
    ):
        self.sample_interval = sample_interval
        self.history_length = history_length
        self._byte_counts: dict[str, int] = defaultdict(int)
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=history_length))
        self._lock = threading.Lock()
        self._running = False
        self._handle: pydivert.WinDivert | None = None

    @staticmethod
    def _in_range(ip: str) -> bool:
        return ip.startswith(HOTSPOT_SUBNET_PREFIX + ".") and ip != GATEWAY_IP

    def _client_ip(self, src: str, dst: str) -> str | None:
        """Which endpoint is the hotspot client this packet belongs to.

        Upload  (client -> internet):  src is the client.
        Download(internet -> client):  dst is the client.
        Gateway (.1) traffic is not a client and is ignored as an owner.
        """
        if self._in_range(src):
            return src
        if self._in_range(dst):
            return dst
        return None

    def _capture_loop(self) -> None:
        with pydivert.WinDivert(FILTER) as w:
            self._handle = w
            while self._running:
                try:
                    packet = w.recv()
                except OSError:
                    break
                client = self._client_ip(packet.src_addr, packet.dst_addr)
                if client is not None:
                    with self._lock:
                        self._byte_counts[client] += len(packet.raw.tobytes())
                w.send(packet)
        self._handle = None

    def _sample_loop(self) -> None:
        while self._running:
            time.sleep(self.sample_interval)
            with self._lock:
                for ip in list(self._byte_counts.keys()):
                    total = self._byte_counts[ip]
                    self._history[ip].append(total)
                    self._byte_counts[ip] = 0

    def start_background(self) -> None:
        self._running = True
        threading.Thread(target=self._capture_loop, daemon=True).start()
        threading.Thread(target=self._sample_loop, daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._handle is not None:
            self._handle.close()

    def snapshot(self) -> dict[str, list[int]]:
        with self._lock:
            return {ip: list(h) for ip, h in self._history.items()}

    def current_rate_bps(self, ip: str, samples: int = 5) -> float:
        with self._lock:
            hist = list(self._history.get(ip, ()))
        recent = hist[-samples:]
        if not recent:
            return 0.0
        return sum(recent) / (len(recent) * self.sample_interval)


def _median(values: list[float]) -> float:
    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2


def compute_suspicious(rates: dict[str, float]) -> dict[str, bool]:
    """Flags devices whose recent bandwidth is well above their peers'.

    Compares each device against the median of every OTHER device
    (leave-one-out), not the whole group's median - with only two
    devices, including the outlier itself in its own comparison group
    drags the median up and hides it.
    """
    result: dict[str, bool] = {}
    items = list(rates.items())
    for ip, rate in items:
        if rate <= 0:
            result[ip] = False
            continue
        others = sorted(r for other_ip, r in items if other_ip != ip and r > 0)
        if not others:
            # no peer to compare against - fall back to a stricter absolute floor
            result[ip] = rate > SUSPICIOUS_FLOOR_BPS * 2
            continue
        threshold = max(SUSPICIOUS_FLOOR_BPS, _median(others) * SUSPICIOUS_MULTIPLIER)
        result[ip] = rate > threshold
    return result
