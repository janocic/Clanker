"""Local web API + static file server for the Astro dashboard.

Serves the built Astro site (web/dist) and a small JSON API from the
same origin (127.0.0.1) so the browser needs no CORS setup at all.
"""

import ipaddress
import re
from pathlib import Path

from flask import Flask, jsonify, request

from . import access_control
from .blocklist import Blocklist
from .dashboard_state import DashboardState
from .devices import get_arp_table
from .nicknames import Nicknames
from .traffic_meter import TrafficMeter, compute_suspicious

WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _normalize_domain(raw: str) -> str | None:
    value = raw.strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/")[0].split(":")[0]
    if not value or not _HOSTNAME_RE.match(value):
        return None
    return value


def create_app(
    state: DashboardState,
    blocklist: Blocklist,
    traffic_meter: TrafficMeter | None = None,
    nicknames: Nicknames | None = None,
) -> Flask:
    app = Flask(__name__, static_folder=str(WEB_DIST), static_url_path="")
    nicks = nicknames or Nicknames()

    @app.get("/")
    def index():
        if not (WEB_DIST / "index.html").exists():
            return (
                "web/dist nije izgraden. Pokreni: cd web && npm install && npm run build",
                503,
            )
        return app.send_static_file("index.html")

    @app.get("/api/devices")
    def api_devices():
        _, stats = state.snapshot()
        arp = get_arp_table()
        blocked_ips = access_control.list_blocked()
        traffic = traffic_meter.snapshot() if traffic_meter else {}

        rates = {ip: traffic_meter.current_rate_bps(ip) for ip in traffic} if traffic_meter else {}
        traffic_suspicious = compute_suspicious(rates)

        rows = []
        for ip in sorted(set(arp) | set(stats) | set(traffic)):
            s = stats.get(ip, {"total": 0, "blocked": 0, "ai": 0, "mac": arp.get(ip, "?")})
            mac = arp.get(ip, s.get("mac", "?"))
            ai_hits = s.get("ai", 0)
            high_traffic = traffic_suspicious.get(ip, False)
            rows.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "nickname": nicks.get(mac),
                    "total": s["total"],
                    "blockedQueries": s["blocked"],
                    "aiHits": ai_hits,
                    "networkBlocked": ip in blocked_ips,
                    "traffic": traffic.get(ip, []),
                    "bandwidthBps": round(rates.get(ip, 0.0), 1),
                    "highTraffic": high_traffic,
                    # A device is suspicious if it actually reached AI/DoH
                    # domains OR is transferring far more than its peers.
                    # AI hits matter even at near-zero bandwidth, since a
                    # blocked request transfers almost nothing.
                    "suspicious": ai_hits > 0 or high_traffic,
                }
            )
        return jsonify(rows)

    @app.get("/api/queries")
    def api_queries():
        recent, _ = state.snapshot()
        return jsonify(recent)

    @app.post("/api/nickname")
    def api_nickname():
        body = request.get_json(silent=True) or {}
        mac = str(body.get("mac", "")).strip()
        if not re.match(r"^[0-9a-fA-F]{2}([-:][0-9a-fA-F]{2}){5}$", mac):
            return jsonify({"error": "neispravna MAC adresa"}), 400
        nickname = nicks.set(mac, str(body.get("nickname", "")))
        return jsonify({"ok": True, "mac": mac.lower(), "nickname": nickname})

    @app.get("/api/blocklist")
    def api_blocklist_get():
        return jsonify(blocklist.snapshot())

    @app.post("/api/blocklist")
    def api_blocklist_add():
        raw = (request.get_json(silent=True) or {}).get("domain", "")
        domain = _normalize_domain(raw)
        if not domain:
            return jsonify({"error": "neispravna domena"}), 400
        blocklist.add_live_domain(domain)
        return jsonify({"ok": True, "domain": domain})

    @app.delete("/api/blocklist")
    def api_blocklist_delete():
        raw = (request.get_json(silent=True) or {}).get("domain", "")
        domain = _normalize_domain(raw) or raw.strip().lower()
        blocklist.remove_live_domain(domain)
        return jsonify({"ok": True})

    @app.post("/api/block")
    def api_block():
        ip = (request.get_json(silent=True) or {}).get("ip", "")
        if not _valid_ip(ip):
            return jsonify({"error": "invalid ip"}), 400
        access_control.block_ip(ip)
        if ip not in access_control.refresh_now():
            return jsonify(
                {"error": "Firewall pravilo nije primijenjeno. Pokreni guard kao Administrator."}
            ), 500
        return jsonify({"ok": True})

    @app.post("/api/unblock")
    def api_unblock():
        ip = (request.get_json(silent=True) or {}).get("ip", "")
        if not _valid_ip(ip):
            return jsonify({"error": "invalid ip"}), 400
        access_control.unblock_ip(ip)
        if ip in access_control.refresh_now():
            return jsonify(
                {"error": "Firewall pravilo nije uklonjeno. Pokreni guard kao Administrator."}
            ), 500
        return jsonify({"ok": True})

    return app
