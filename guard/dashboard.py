"""Live terminal dashboard: renders a shared DashboardState (see
dashboard_state.py) as connected devices + recent DNS activity."""

import time

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from . import access_control
from .dashboard_state import DashboardState
from .devices import get_arp_table


def render(state: DashboardState) -> Layout:
    recent, stats = state.snapshot()
    blocked_ips = access_control.list_blocked()

    layout = Layout()
    layout.split_column(Layout(name="devices", ratio=1), Layout(name="queries", ratio=2))

    devices_table = Table(title="Uredaji (ARP)")
    devices_table.add_column("IP")
    devices_table.add_column("MAC")
    devices_table.add_column("Upiti")
    devices_table.add_column("Blokirano")
    devices_table.add_column("Pristup")

    arp = get_arp_table()
    for ip in sorted(set(arp) | set(stats)):
        stat = stats.get(ip, {"total": 0, "blocked": 0, "mac": arp.get(ip, "?")})
        mac = arp.get(ip, stat.get("mac", "?"))
        access = "[bold red]ODSPOJEN[/]" if ip in blocked_ips else "[green]ok[/]"
        style = "bold red" if stat["blocked"] else ""
        devices_table.add_row(ip, mac, str(stat["total"]), str(stat["blocked"]), access, style=style)

    queries_table = Table(title="Zadnji DNS upiti")
    queries_table.add_column("Vrijeme")
    queries_table.add_column("Klijent")
    queries_table.add_column("Domena")
    queries_table.add_column("Status")

    for entry in recent:
        ts = time.strftime("%H:%M:%S", time.localtime(entry["ts"]))
        if entry.get("blocked") and entry.get("severity") == "suspected":
            status = "[orange3]AI ?[/]"
        elif entry.get("blocked"):
            status = "[bold red]AI ![/]"
        else:
            status = "[green]ok[/]"
        queries_table.add_row(ts, entry["client_ip"], entry["qname"], status)

    layout["devices"].update(Panel(devices_table))
    layout["queries"].update(Panel(queries_table))
    return layout


def run(state: DashboardState) -> None:
    with Live(render(state), refresh_per_second=2, screen=True) as live:
        while True:
            live.update(render(state))
            time.sleep(0.5)
