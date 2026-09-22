"""CLI entrypoint. Run as `python -m guard.main <command>`."""

import argparse
import threading

from . import devices, hotspot
from .blocklist import Blocklist
from .dns_blocker import DNSBlocker


def cmd_dns(args) -> None:
    bl = Blocklist()
    blocker = DNSBlocker(blocklist=bl)
    print("[guard] DNS blocker presrece udp/53 preko WinDivert-a (ICS i dalje rjesava dopusteno)")
    print(f"[guard] Blokirano {len(bl.domains)} domena, {len(bl.keywords)} kljucnih rijeci")
    blocker.start_background()

    if args.no_dashboard:
        print("[guard] Dashboard iskljucen, Ctrl+C za izlaz")
        threading.Event().wait()
    else:
        from . import dashboard

        dashboard.run()


def cmd_devices(args) -> None:
    table = devices.get_arp_table(force=True)
    if not table:
        print("Nema uredaja u ARP tablici (jesi li spojen na hotspot mrezu?)")
    for ip, mac in sorted(table.items()):
        print(f"{ip:<16} {mac}")


def cmd_hotspot_check(args) -> None:
    info = hotspot.check_hosted_network_support()
    print(info["raw"])
    if info["supported_line"]:
        print(f">> {info['supported_line']}")


def cmd_hotspot_start(args) -> None:
    result = hotspot.start_legacy_hotspot(args.ssid, args.password)
    for step, (code, out, err) in result.items():
        print(f"--- {step} (exit {code}) ---")
        print(out or err)


def cmd_hotspot_stop(args) -> None:
    code, out, err = hotspot.stop_legacy_hotspot()
    print(out or err)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard", description="CTF AI-blokada: DNS proxy i monitoring")
    sub = parser.add_subparsers(dest="command", required=True)

    p_dns = sub.add_parser("dns", help="Pokreni DNS blocker (+ dashboard). Zahtijeva Administrator shell.")
    p_dns.add_argument("--no-dashboard", action="store_true")
    p_dns.set_defaults(func=cmd_dns)

    p_dev = sub.add_parser("devices", help="Prikazi ARP tablicu (spojeni uredaji)")
    p_dev.set_defaults(func=cmd_devices)

    p_hc = sub.add_parser("hotspot-check", help="Provjeri podrzava li WiFi adapter hosted network")
    p_hc.set_defaults(func=cmd_hotspot_check)

    p_hs = sub.add_parser("hotspot-start", help="Pokreni legacy hosted network hotspot")
    p_hs.add_argument("--ssid", required=True)
    p_hs.add_argument("--password", required=True)
    p_hs.set_defaults(func=cmd_hotspot_start)

    p_hp = sub.add_parser("hotspot-stop", help="Zaustavi hosted network hotspot")
    p_hp.set_defaults(func=cmd_hotspot_stop)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
