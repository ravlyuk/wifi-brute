from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import objc
from CoreLocation import (
    CLLocationManager,
    kCLAuthorizationStatusAuthorizedAlways,
    kCLAuthorizationStatusAuthorizedWhenInUse,
    kCLAuthorizationStatusDenied,
    kCLAuthorizationStatusNotDetermined,
    kCLAuthorizationStatusRestricted,
)
from CoreWLAN import (
    CWWiFiClient,
    kCWSecurityEnterprise,
    kCWSecurityNone,
    kCWSecurityWPA2Enterprise,
    kCWSecurityWPA2Personal,
    kCWSecurityWPA3Enterprise,
    kCWSecurityWPA3Personal,
    kCWSecurityWPA3Transition,
    kCWSecurityWPAEnterprise,
    kCWSecurityWPAEnterpriseMixed,
    kCWSecurityWPAPersonal,
    kCWSecurityWPAPersonalMixed,
)
from Foundation import NSObject
from pydantic import ValidationError

from wifi_connector.models import SecurityKind, WifiNetwork

_PERSONAL_MODES = {
    int(kCWSecurityWPAPersonal),
    int(kCWSecurityWPAPersonalMixed),
    int(kCWSecurityWPA2Personal),
    int(kCWSecurityWPA3Personal),
    int(kCWSecurityWPA3Transition),
}
_ENTERPRISE_MODES = {
    int(kCWSecurityWPAEnterprise),
    int(kCWSecurityWPAEnterpriseMixed),
    int(kCWSecurityWPA2Enterprise),
    int(kCWSecurityEnterprise),
    int(kCWSecurityWPA3Enterprise),
}


def has_location_access(status: int) -> bool:
    return status in {
        int(kCLAuthorizationStatusAuthorizedAlways),
        int(kCLAuthorizationStatusAuthorizedWhenInUse),
    }


def location_hint(status: int) -> str | None:
    if has_location_access(status):
        return None
    if status == int(kCLAuthorizationStatusNotDetermined):
        return (
            "macOS ховає назви мереж без Геолокації. "
            "Натисніть «Дозволити локацію» і підтвердіть діалог."
        )
    if status in {
        int(kCLAuthorizationStatusDenied),
        int(kCLAuthorizationStatusRestricted),
    }:
        return (
            "Геолокацію заборонено, тому видно лише поточну мережу. "
            "Натисніть «Дозволити локацію» і ввімкніть Wi‑Fi Connect."
        )
    return "Немає доступу до Геолокації — назви сусідніх мереж приховані."


class LocationController(NSObject):
    manager: CLLocationManager
    on_change: Callable[[int], None] | None

    def init(self) -> "LocationController | None":
        self = objc.super(LocationController, self).init()
        if self is None:
            return None
        self.manager = CLLocationManager.alloc().init()
        self.manager.setDelegate_(self)
        self.on_change = None
        return self

    @objc.python_method
    def status(self) -> int:
        return int(self.manager.authorizationStatus())

    @objc.python_method
    def requestAccess(self) -> None:
        current = self.status()
        if current == int(kCLAuthorizationStatusNotDetermined):
            self.manager.requestWhenInUseAuthorization()
            return
        if has_location_access(current):
            self.manager.startUpdatingLocation()
        callback = self.on_change
        if callback is not None:
            callback(current)

    def locationManagerDidChangeAuthorization_(self, manager: CLLocationManager) -> None:
        current = int(manager.authorizationStatus())
        if has_location_access(current):
            manager.startUpdatingLocation()
        callback = self.on_change
        if callback is not None:
            callback(current)

    def locationManager_didChangeAuthorizationStatus_(
        self,
        manager: CLLocationManager,
        _status: int,
    ) -> None:
        self.locationManagerDidChangeAuthorization_(manager)

    def locationManager_didFailWithError_(self, _manager: CLLocationManager, _error: object) -> None:
        return None


def _ssid_from_network(network: Any) -> str | None:
    ssid = network.ssid()
    if ssid:
        return str(ssid)

    payload = network.ssidData()
    if payload is None:
        return None
    try:
        decoded = bytes(payload).decode("utf-8").strip("\x00")
    except (TypeError, UnicodeDecodeError, ValueError):
        return None
    return decoded or None


def _security_from_mode(mode: int | None) -> SecurityKind:
    if mode is None:
        return SecurityKind.UNKNOWN
    if mode == int(kCWSecurityNone):
        return SecurityKind.OPEN
    if mode in _PERSONAL_MODES:
        return SecurityKind.PERSONAL
    if mode in _ENTERPRISE_MODES:
        return SecurityKind.ENTERPRISE
    return SecurityKind.UNKNOWN


def _current_ssid(interface: Any) -> str | None:
    ssid = interface.ssid()
    return str(ssid) if ssid else None


def read_current_ssid() -> str | None:
    interface = CWWiFiClient.sharedWiFiClient().interface()
    if interface is None:
        return None
    return _current_ssid(interface)


def _wait_until_disconnected(interface: Any, *, timeout_seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _current_ssid(interface) is None:
            return True
        time.sleep(0.2)
    return _current_ssid(interface) is None


def associate_with_network(
    ssid: str,
    password: str,
    *,
    verify_password: bool = False,
) -> tuple[bool | None, str | None]:
    """Associate via CoreWLAN.

    Returns ``(True, None)`` on success, ``(False, message)`` on failure, and
    ``(None, None)`` when the SSID is missing from the scan cache (caller may
    fall back to ``networksetup``).

    When ``verify_password`` is True, an existing connection to the target SSID
    is torn down before the password is tested.
    """
    interface = CWWiFiClient.sharedWiFiClient().interface()
    if interface is None:
        return False, "Wi-Fi interface was not found"

    target_ssid = ssid.strip()
    if not target_ssid:
        return False, "SSID is empty"

    if _current_ssid(interface) == target_ssid:
        if not verify_password:
            return True, None
        interface.disassociate()
        if not _wait_until_disconnected(interface):
            return False, "Не вдалося від'єднатися для перевірки пароля"

    found, scan_error = interface.scanForNetworksWithName_error_(target_ssid, None)
    if scan_error is not None and found is None:
        return False, str(scan_error)

    target_network = None
    for raw in found or []:
        if _ssid_from_network(raw) == target_ssid:
            target_network = raw
            break

    if target_network is None:
        return None, None

    success, error = interface.associateToNetwork_password_error_(
        target_network,
        password,
        None,
    )
    if not success:
        detail = str(error).strip() if error is not None else "association failed"
        return False, detail

    if _current_ssid(interface) == target_ssid:
        return True, None

    return False, f"Не вдалося підтвердити підключення до {target_ssid}"


def prepare_password_verification(ssid: str) -> None:
    interface = CWWiFiClient.sharedWiFiClient().interface()
    if interface is None:
        return
    target_ssid = ssid.strip()
    if not target_ssid or _current_ssid(interface) != target_ssid:
        return
    interface.disassociate()
    _wait_until_disconnected(interface)


def scan_nearby_networks(status: int | None = None) -> tuple[list[WifiNetwork], int]:
    if status is None:
        status = int(CLLocationManager.authorizationStatus())

    interface = CWWiFiClient.sharedWiFiClient().interface()
    if interface is None:
        raise RuntimeError("Wi-Fi interface was not found")

    found, error = interface.scanForNetworksWithName_error_(None, None)
    if error is not None and found is None:
        raise RuntimeError(str(error))

    current = _current_ssid(interface)
    networks: dict[str, WifiNetwork] = {}
    for raw in found or []:
        ssid = _ssid_from_network(raw)
        if not ssid:
            continue
        rssi = int(raw.rssiValue())
        try:
            parsed = WifiNetwork(
                ssid=ssid,
                security=_security_from_mode(int(raw.securityMode())),
                rssi_dbm=rssi,
                is_current=bool(current and ssid == current),
            )
        except ValidationError:
            continue
        existing = networks.get(ssid)
        if existing is None or (parsed.rssi_dbm or -999) > (existing.rssi_dbm or -999):
            if existing and existing.is_current:
                parsed = parsed.model_copy(update={"is_current": True})
            networks[ssid] = parsed

    return list(networks.values()), status
