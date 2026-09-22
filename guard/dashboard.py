"""Live terminal dashboard: tails logs/dns_queries.jsonl and shows
connected devices (from ARP) plus recent DNS activity, highlighting
blocked (AI-related) queries."""

import json
import time
from collections import defaultdict, deque
from pathlib import Path

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .devices import get_arp_table

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "dns_queries.jsonl"


class DashboardState:
    def __init__(self, max_recent: int = 20):
        self.recent = deque(maxlen=max_recent)
        self.stats = defaultdict(lambda: {"total": 0, "blocked": 0, "mac": "?"})
        LOG_PATH.parent.mkdir(exist_ok=True)
        LOG_PATH.touch(exist_ok=True)
        with LOG_PATH.open("r", encoding="utf-8") as f:
            f.seek(0, 2)
            self._pos = f.tell()

    def poll(self) -> None:
        with LOG_PATH.open("r", encoding="utf-8") as f:
            f.seek(self._pos)
            lines = f.readlines()
            self._pos = f.tell()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.recent.appendleft(entry)
            stat = self.stats[entry["client_ip"]]
            stat["total"] += 1
            stat["mac"] = entry.get("client_mac", "?")
            if entry.get("blocked"):
                stat["blocked"] += 1


def render(state: DashboardState) -> Layout:
    layout = Layout()
    layout.split_column(Layout(name="devices", ratio=1), Layout(name="queries", ratio=2))

    devices_table = Table(title="Uredaji (ARP)")
    devices_table.add_column("IP")
    devices_table.add_column("MAC")
    devices_table.add_column("Upiti")
    devices_table.add_column("Blokirano")

    arp = get_arp_table()
    for ip in sorted(set(arp) | set(state.stats)):
        stat = state.stats.get(ip, {"total": 0, "blocked": 0, "mac": arp.get(ip, "?")})
        mac = arp.get(ip, stat.get("mac", "?"))
        blocked = stat["blocked"]
        style = "bold red" if blocked else ""
        devices_table.add_row(ip, mac, str(stat["total"]), str(blocked), style=style)

    queries_table = Table(title="Zadnji DNS upiti")
    queries_table.add_column("Vrijeme")
    queries_table.add_column("Klijent")
    queries_table.add_column("Domena")
    queries_table.add_column("Status")

    for entry in state.recent:
        ts = time.strftime("%H:%M:%S", time.localtime(entry["ts"]))
        status = "[bold red]BLOKIRANO[/]" if entry.get("blocked") else "[green]ok[/]"
        queries_table.add_row(ts, entry["client_ip"], entry["qname"], status)

    layout["devices"].update(Panel(devices_table))
    layout["queries"].update(Panel(queries_table))
    return layout


def run() -> None:
    state = DashboardState()
    with Live(render(state), refresh_per_second=2, screen=True) as live:
        while True:
            state.poll()
            live.update(render(state))
            time.sleep(0.5)
