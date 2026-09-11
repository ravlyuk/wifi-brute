from __future__ import annotations

import argparse
import asyncio
import sys

from pydantic import ValidationError

from wifi_connector.models import JoinRequest
from wifi_connector.wifi_service import default_password, join_network, list_visible_networks


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Join a Wi-Fi network you select on this Mac.",
    )
    parser.add_argument("--ssid", help="Exact SSID of a network you are allowed to join")
    parser.add_argument(
        "--password",
        default=default_password(),
        help="PSK for that network (default: the password you configured)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print visible networks and exit",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Skip the GUI and join from the command line",
    )
    return parser


async def _print_networks() -> int:
    networks, hint = await list_visible_networks()
    if hint:
        print(hint, file=sys.stderr)
    if not networks:
        print("No named networks available.")
        return 0
    for network in networks:
        marker = "*" if network.is_current else " "
        signal = f"{network.rssi_dbm} dBm" if network.rssi_dbm is not None else "n/a"
        print(f"{marker} {network.ssid}  [{network.security.value}]  {signal}")
    return 0


async def _join_from_cli(ssid: str, password: str) -> int:
    try:
        request = JoinRequest(ssid=ssid, password=password)
    except ValidationError as error:
        print(error.errors()[0]["msg"], file=sys.stderr)
        return 2

    result = await join_network(request)
    print(result.message)
    return 0 if result.is_connected else 1


def main() -> None:
    args = _build_parser().parse_args()

    if args.list:
        raise SystemExit(asyncio.run(_print_networks()))

    if args.cli or args.ssid:
        if not args.ssid:
            print("--ssid is required in CLI mode", file=sys.stderr)
            raise SystemExit(2)
        raise SystemExit(asyncio.run(_join_from_cli(args.ssid, args.password)))

    from wifi_connector.gui import run_app

    run_app()


if __name__ == "__main__":
    main()
