from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from wifi_connector.models import JoinRequest, JoinResult, SecurityKind, TestAllProgress, WifiNetwork
from wifi_connector.password_config import load_password_config, shared_passwords_path
from wifi_connector.wifi_service import (
    _FAST_CONNECTION_POLL_INTERVAL_SECONDS,
    _FAST_CONNECTION_WAIT_SECONDS,
    build_test_passwords,
    default_password,
    get_common_test_passwords,
    join_network,
    test_all_networks,
    _wait_for_ssid,
)
from wifi_connector.scanner import associate_with_network


class JoinNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_passes_verify_password_to_corewlan(self) -> None:
        request = JoinRequest(ssid="Room_1502", password="12345678")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(False, "incorrect password")),
            ) as to_thread_mock,
            patch(
                "wifi_connector.wifi_service._join_via_networksetup",
                AsyncMock(),
            ),
        ):
            result = await join_network(request, verify_password=True)

        self.assertFalse(result.is_connected)
        to_thread_mock.assert_awaited_once()
        args, kwargs = to_thread_mock.await_args
        self.assertIs(args[0], associate_with_network)
        self.assertEqual(args[1], "Room_1502")
        self.assertEqual(args[2], "12345678")
        self.assertTrue(kwargs.get("verify_password"))

    async def test_uses_corewlan_when_association_succeeds(self) -> None:
        request = JoinRequest(ssid="Room_1502", password="Nam1502@@")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(True, None)),
            ),
            patch(
                "wifi_connector.wifi_service._join_via_networksetup",
                AsyncMock(),
            ) as networksetup_mock,
        ):
            result = await join_network(request, fast_verify=True)

        self.assertTrue(result.is_connected)
        self.assertEqual(result.ssid, "Room_1502")
        self.assertEqual(result.password, "Nam1502@@")
        networksetup_mock.assert_not_awaited()

    async def test_falls_back_to_networksetup_when_network_is_not_in_scan(self) -> None:
        request = JoinRequest(ssid="Hidden WiFi", password="password123")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(None, None)),
            ),
            patch(
                "wifi_connector.wifi_service._join_via_networksetup",
                AsyncMock(
                    return_value=JoinResult(
                        is_connected=True,
                        ssid="Hidden WiFi",
                        interface="en0",
                        message="ok",
                    )
                ),
            ) as networksetup_mock,
        ):
            result = await join_network(request, fast_verify=True)

        self.assertTrue(result.is_connected)
        networksetup_mock.assert_awaited_once()

    async def test_reports_corewlan_failure_without_networksetup(self) -> None:
        request = JoinRequest(ssid="Office WiFi", password="password123")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(False, "incorrect password")),
            ),
            patch(
                "wifi_connector.wifi_service._join_via_networksetup",
                AsyncMock(),
            ) as networksetup_mock,
        ):
            result = await join_network(request)

        self.assertFalse(result.is_connected)
        self.assertIn("incorrect password", result.message)
        networksetup_mock.assert_not_awaited()

    async def test_reports_success_only_after_ssid_is_confirmed(self) -> None:
        request = JoinRequest(ssid="Office WiFi", password="password123")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(None, None)),
            ),
            patch(
                "wifi_connector.wifi_service._join_via_networksetup",
                AsyncMock(
                    return_value=JoinResult(
                        is_connected=True,
                        ssid="Office WiFi",
                        interface="en0",
                        message="ok",
                    )
                ),
            ),
        ):
            result = await join_network(request)

        self.assertTrue(result.is_connected)
        self.assertEqual(result.ssid, "Office WiFi")

    async def test_reports_failure_when_target_ssid_is_never_active(self) -> None:
        request = JoinRequest(ssid="Office WiFi", password="password123")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(None, None)),
            ),
            patch(
                "wifi_connector.wifi_service._join_via_networksetup",
                AsyncMock(
                    return_value=JoinResult(
                        is_connected=False,
                        ssid="Office WiFi",
                        interface="en0",
                        message="Не вдалося підтвердити",
                    )
                ),
            ),
        ):
            result = await join_network(request)

        self.assertFalse(result.is_connected)
        self.assertIn("Не вдалося підтвердити", result.message)

    async def test_does_not_poll_after_command_failure(self) -> None:
        request = JoinRequest(ssid="Office WiFi", password="password123")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(None, None)),
            ),
            patch(
                "wifi_connector.wifi_service._run_command",
                AsyncMock(return_value=(1, "", "Failed to join network")),
            ),
            patch(
                "wifi_connector.wifi_service._wait_for_ssid",
                AsyncMock(),
            ) as wait_for_ssid_mock,
        ):
            result = await join_network(request)

        self.assertFalse(result.is_connected)
        wait_for_ssid_mock.assert_not_awaited()

    async def test_fast_verify_uses_shorter_wait_timeout(self) -> None:
        request = JoinRequest(ssid="Office WiFi", password="password123")

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.asyncio.to_thread",
                AsyncMock(return_value=(None, None)),
            ),
            patch(
                "wifi_connector.wifi_service._run_command",
                AsyncMock(return_value=(0, "", "")),
            ),
            patch(
                "wifi_connector.wifi_service._read_current_ssid",
                AsyncMock(return_value="Previous WiFi"),
            ),
            patch(
                "wifi_connector.wifi_service._wait_for_ssid",
                AsyncMock(return_value=False),
            ) as wait_for_ssid_mock,
        ):
            await join_network(request, fast_verify=True)

        wait_for_ssid_mock.assert_awaited_once_with(
            "en0",
            "Office WiFi",
            timeout_seconds=_FAST_CONNECTION_WAIT_SECONDS,
            poll_interval_seconds=_FAST_CONNECTION_POLL_INTERVAL_SECONDS,
        )


class WaitForSsidTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_true_when_target_appears_during_wait(self) -> None:
        with (
            patch(
                "wifi_connector.wifi_service._read_current_ssid",
                AsyncMock(side_effect=["Other", "Target"]),
            ),
            patch("wifi_connector.wifi_service.asyncio.sleep", AsyncMock()),
        ):
            is_connected = await _wait_for_ssid(
                "en0",
                "Target",
                timeout_seconds=5.0,
                poll_interval_seconds=0.5,
            )

        self.assertTrue(is_connected)

    async def test_returns_false_after_timeout(self) -> None:
        perf_counter_values = iter([0.0, 0.0, 0.6, 1.2])

        with (
            patch(
                "wifi_connector.wifi_service._read_current_ssid",
                AsyncMock(return_value="Other"),
            ),
            patch("wifi_connector.wifi_service.asyncio.sleep", AsyncMock()),
            patch(
                "wifi_connector.wifi_service.time.perf_counter",
                side_effect=lambda: next(perf_counter_values),
            ),
        ):
            is_connected = await _wait_for_ssid(
                "en0",
                "Target",
                timeout_seconds=1.0,
                poll_interval_seconds=0.5,
            )

        self.assertFalse(is_connected)


class TestAllNetworksTests(unittest.IsolatedAsyncioTestCase):
    async def test_skips_open_networks(self) -> None:
        networks = [
            WifiNetwork(ssid="Open Cafe", security=SecurityKind.OPEN),
            WifiNetwork(ssid="Home WiFi", security=SecurityKind.PERSONAL),
        ]

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.join_network",
                AsyncMock(
                    return_value=JoinResult(
                        is_connected=True,
                        ssid="Home WiFi",
                        interface="en0",
                        message="ok",
                    )
                ),
            ) as join_network_mock,
        ):
            result = await test_all_networks(networks, ["password123"])

        join_network_mock.assert_awaited_once_with(
            JoinRequest(ssid="Home WiFi", password="password123", interface="en0"),
            fast_verify=True,
            verify_password=True,
        )
        self.assertEqual(len(result.results), 1)
        self.assertGreaterEqual(result.elapsed_seconds, 0.0)

    async def test_reports_progress_for_each_network(self) -> None:
        networks = [
            WifiNetwork(ssid="Net A", security=SecurityKind.PERSONAL),
            WifiNetwork(ssid="Net B", security=SecurityKind.PERSONAL),
        ]
        progress_snapshots: list[TestAllProgress] = []

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.join_network",
                AsyncMock(
                    side_effect=[
                        JoinResult(
                            is_connected=True,
                            ssid="Net A",
                            interface="en0",
                            message="ok",
                            password="password123",
                        ),
                        JoinResult(
                            is_connected=False,
                            ssid="Net B",
                            interface="en0",
                            message="fail",
                        ),
                    ]
                ),
            ),
        ):
            result = await test_all_networks(
                networks,
                ["password123"],
                on_progress=lambda progress: progress_snapshots.append(progress),
            )

        self.assertEqual(len(progress_snapshots), 4)
        self.assertTrue(progress_snapshots[0].is_active)
        self.assertEqual(progress_snapshots[0].completed, [])
        self.assertFalse(progress_snapshots[1].is_active)
        self.assertEqual(len(progress_snapshots[1].completed), 1)
        self.assertEqual(len(progress_snapshots[1].successful), 1)
        self.assertEqual(progress_snapshots[1].successful[0].ssid, "Net A")
        self.assertEqual(progress_snapshots[1].successful[0].password, "password123")
        self.assertEqual(len(result.successful), 1)
        self.assertEqual(result.successful[0].password, "password123")
        self.assertEqual(result.successful_count, 1)
        self.assertEqual(result.failed_count, 1)
        self.assertGreater(result.average_seconds_per_network, 0.0)

    async def test_stops_when_requested(self) -> None:
        networks = [
            WifiNetwork(ssid="Net A", security=SecurityKind.PERSONAL),
            WifiNetwork(ssid="Net B", security=SecurityKind.PERSONAL),
            WifiNetwork(ssid="Net C", security=SecurityKind.PERSONAL),
        ]
        stop_after_first = False

        def should_stop() -> bool:
            return stop_after_first

        async def fake_join(
            request: JoinRequest,
            *,
            fast_verify: bool = False,
            verify_password: bool = False,
        ) -> JoinResult:
            nonlocal stop_after_first
            stop_after_first = True
            return JoinResult(
                is_connected=False,
                ssid=request.ssid,
                interface="en0",
                message="fail",
            )

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.join_network",
                side_effect=fake_join,
            ),
        ):
            result = await test_all_networks(
                networks,
                ["password123"],
                should_stop=should_stop,
            )

        self.assertTrue(result.was_stopped)
        self.assertEqual(len(result.results), 1)
        self.assertFalse(result.results[0].is_connected)

    async def test_tries_next_password_after_failure(self) -> None:
        networks = [WifiNetwork(ssid="Hotel WiFi", security=SecurityKind.PERSONAL)]
        passwords = ["11111111", "87654321"]

        with (
            patch(
                "wifi_connector.wifi_service.resolve_wifi_interface",
                AsyncMock(return_value="en0"),
            ),
            patch(
                "wifi_connector.wifi_service.join_network",
                AsyncMock(
                    side_effect=[
                        JoinResult(
                            is_connected=False,
                            ssid="Hotel WiFi",
                            interface="en0",
                            message="fail",
                        ),
                        JoinResult(
                            is_connected=True,
                            ssid="Hotel WiFi",
                            interface="en0",
                            message="ok",
                            password="87654321",
                        ),
                    ]
                ),
            ) as join_network_mock,
        ):
            result = await test_all_networks(networks, passwords)

        self.assertEqual(join_network_mock.await_count, 2)
        self.assertEqual(len(result.results), 1)
        self.assertTrue(result.results[0].is_connected)
        self.assertEqual(result.results[0].password, "87654321")


class BuildTestPasswordsTests(unittest.TestCase):
    def test_uses_common_passwords_when_manual_is_empty(self) -> None:
        passwords = build_test_passwords("")
        self.assertEqual(passwords, list(get_common_test_passwords()))

    def test_manual_password_only_when_common_disabled(self) -> None:
        passwords = build_test_passwords("Nam1502@@", include_common=False)
        self.assertEqual(passwords, ["Nam1502@@"])

    def test_returns_empty_when_common_disabled_and_manual_missing(self) -> None:
        self.assertEqual(build_test_passwords("", include_common=False), [])

    def test_deduplicates_manual_password(self) -> None:
        passwords = build_test_passwords("12345678")
        self.assertEqual(passwords.count("12345678"), 1)

    def test_includes_manual_password_before_common(self) -> None:
        passwords = build_test_passwords("Nam1502@@")
        self.assertEqual(passwords[0], "Nam1502@@")
        self.assertIn("12345678", passwords)
        self.assertEqual(len(passwords), len(set(passwords)))


class PasswordConfigTests(unittest.TestCase):
    def test_loads_shared_yaml(self) -> None:
        shared_path = shared_passwords_path()
        self.assertIsNotNone(shared_path)
        config = load_password_config(path=shared_path)
        self.assertEqual(config.default_password, "12345678")
        self.assertEqual(len(config.passwords), 53)
        self.assertIn("01011990", config.passwords)
        self.assertIn("09012345", config.passwords)

    def test_default_password_matches_yaml(self) -> None:
        shared_path = shared_passwords_path()
        self.assertIsNotNone(shared_path)
        config = load_password_config(path=shared_path)
        self.assertEqual(default_password(), config.default_password)


if __name__ == "__main__":
    unittest.main()
