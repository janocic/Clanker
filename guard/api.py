"""Local web API + static file server for the Astro dashboard.

Serves the built Astro site (web/dist) and a small JSON API from the
same origin (127.0.0.1) so the browser needs no CORS setup at all.
"""

import ipaddress
from pathlib import Path

from flask import Flask, jsonify, request

from . import access_control
from .dashboard_state import DashboardState
from .devices import get_arp_table

WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def create_app(state: DashboardState) -> Flask:
    app = Flask(__name__, static_folder=str(WEB_DIST), static_url_path="")

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

        rows = []
        for ip in sorted(set(arp) | set(stats)):
            s = stats.get(ip, {"total": 0, "blocked": 0, "mac": arp.get(ip, "?")})
            rows.append(
                {
                    "ip": ip,
                    "mac": arp.get(ip, s.get("mac", "?")),
                    "total": s["total"],
                    "blockedQueries": s["blocked"],
                    "networkBlocked": ip in blocked_ips,
                }
            )
        return jsonify(rows)

    @app.get("/api/queries")
    def api_queries():
        recent, _ = state.snapshot()
        return jsonify(recent)

    @app.post("/api/block")
    def api_block():
        ip = (request.get_json(silent=True) or {}).get("ip", "")
        if not _valid_ip(ip):
            return jsonify({"error": "invalid ip"}), 400
        access_control.block_ip(ip)
        if ip not in access_control.list_blocked():
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
        if ip in access_control.list_blocked():
            return jsonify(
                {"error": "Firewall pravilo nije uklonjeno. Pokreni guard kao Administrator."}
            ), 500
        return jsonify({"ok": True})

    return app
