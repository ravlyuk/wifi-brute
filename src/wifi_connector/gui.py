from __future__ import annotations

import asyncio
import threading
from typing import Any

from AppKit import (
    NSApp,
    NSApplication,
    NSApplicationActivationPolicyRegular,
    NSBackingStoreBuffered,
    NSButton,
    NSButtonCell,
    NSColor,
    NSEventModifierFlagCommand,
    NSEventModifierFlagOption,
    NSEventModifierFlagShift,
    NSFont,
    NSFontAttributeName,
    NSForegroundColorAttributeName,
    NSMakeRect,
    NSMenu,
    NSMenuItem,
    NSScrollView,
    NSSecureTextField,
    NSTableColumn,
    NSTableView,
    NSTextField,
    NSTextView,
    NSView,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
    NSWorkspace,
)
from Foundation import NSAttributedString, NSIndexSet, NSMakeRange, NSMutableAttributedString, NSObject, NSURL
import objc
from pydantic import ValidationError

from wifi_connector.models import (
    JoinRequest,
    JoinResult,
    SecurityKind,
    TestAllProgress,
    TestAllResult,
    WifiNetwork,
)
from wifi_connector.scanner import LocationController, location_hint
from wifi_connector.password_config import reload_password_config
from wifi_connector.wifi_service import (
    build_test_passwords,
    default_password,
    get_common_test_passwords,
    join_network,
    list_visible_networks,
    test_all_networks,
)

_LOCATION_SETTINGS = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
)

_SECURITY_LABELS = {
    SecurityKind.OPEN: "Відкрита",
    SecurityKind.PERSONAL: "WPA",
    SecurityKind.ENTERPRISE: "Enterprise",
    SecurityKind.UNKNOWN: "—",
}

_PASSWORD_Y_NORMAL = 90.0
_PASSWORD_LABEL_Y_NORMAL = 118.0
_BUTTON_Y_NORMAL = 48.0
_TABLE_Y_NORMAL = 150.0
_TABLE_H_NORMAL = 280.0
_PASSWORD_Y_TESTING = 142.0
_PASSWORD_LABEL_Y_TESTING = 170.0
_BUTTON_Y_TESTING = 100.0
_TABLE_Y_TESTING = 192.0
_TABLE_H_TESTING = 238.0
_SUCCESS_LOG_FRAME = (20.0, 44.0, 580.0, 52.0)
_STATUS_FRAME_NORMAL = (20.0, 12.0, 580.0, 28.0)


def _password_field_frame(y: float = _PASSWORD_Y_NORMAL) -> tuple[float, float, float, float]:
    return (20.0, y, 500.0, 26.0)


def _toggle_password_frame(y: float = _PASSWORD_Y_NORMAL) -> tuple[float, float, float, float]:
    return (530.0, y, 70.0, 26.0)


def _common_passwords_checkbox_frame(label_y: float) -> tuple[float, float, float, float]:
    return (95.0, label_y + 2.0, 18.0, 18.0)


def _common_passwords_caption_frame(label_y: float) -> tuple[float, float, float, float]:
    return (118.0, label_y, 104.0, 22.0)


def _common_passwords_list_button_frame(label_y: float) -> tuple[float, float, float, float]:
    return (226.0, label_y, 78.0, 22.0)


def _format_common_passwords_list() -> str:
    lines = ["Типові паролі для додаткового тестування:", ""]
    lines.extend(
        f"  {index}. {password}"
        for index, password in enumerate(get_common_test_passwords(), start=1)
    )
    return "\n".join(lines)


def _make_checkbox_control(
    frame: tuple[float, float, float, float],
    *,
    is_checked: bool = True,
) -> NSButton:
    button = NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
    cell = NSButtonCell.alloc().init()
    cell.setButtonType_(3)
    cell.setTitle_("")
    cell.setAllowsMixedState_(False)
    cell.setState_(1 if is_checked else 0)
    button.setCell_(cell)
    return button


def _make_inline_button(
    frame: tuple[float, float, float, float],
    title: str,
    target: object,
    action: str,
) -> NSButton:
    button = NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
    button.setBezelStyle_(0)
    button.setBordered_(False)
    button.setTitle_(title)
    button.setFont_(NSFont.systemFontOfSize_(11))
    button.setTarget_(target)
    button.setAction_(action)
    button.setAttributedTitle_(
        NSAttributedString.alloc().initWithString_attributes_(
            title,
            {
                NSForegroundColorAttributeName: NSColor.secondaryLabelColor(),
                NSFontAttributeName: NSFont.systemFontOfSize_(11),
            },
        )
    )
    return button

_BTN_REFRESH = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.82, 0.62, 0.18, 1.0)
_BTN_TEST = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.16, 0.68, 0.48, 1.0)
_BTN_LOCATION = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.32, 0.44, 0.78, 1.0)
_BTN_CONNECT = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.22, 0.52, 0.92, 1.0)
_BTN_STOP = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.88, 0.28, 0.26, 1.0)
_BTN_TOGGLE = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.28, 0.30, 0.34, 1.0)
_LOG_SUCCESS = NSColor.systemGreenColor()


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} с"
    minutes = int(seconds // 60)
    remainder = int(round(seconds % 60))
    if remainder == 60:
        minutes += 1
        remainder = 0
    return f"{minutes} хв {remainder} с"


def _format_test_summary_short(
    result: TestAllResult,
    *,
    total_planned: int,
) -> str:
    prefix = "Зупинено" if result.was_stopped else "Готово"
    tested = len(result.results)
    stats = (
        f"{prefix} · протестовано {tested} · успішно {result.successful_count} · "
        f"провалено {result.failed_count} · "
        f"{_format_duration(result.elapsed_seconds)} · "
        f"{result.average_seconds_per_network:.1f} с/мережу"
    )
    if result.was_stopped:
        stats = f"{stats} · з {total_planned}"
    return stats


def _format_success_line(result: JoinResult) -> str:
    if result.password:
        return f"  ✓ {result.ssid} · {result.password}"
    return f"  ✓ {result.ssid}"


def _format_test_report(
    result: TestAllResult,
    *,
    total_planned: int,
    skipped_open: int,
    skipped_unselected: int,
) -> str:
    title = "Зупинено" if result.was_stopped else "Завершено"
    lines = [
        f"Звіт про тестування Wi‑Fi ({title})",
        "",
        f"Протестовано: {len(result.results)}",
        f"Успішно: {result.successful_count}",
        f"Провалено: {result.failed_count}",
        f"Загальний час: {_format_duration(result.elapsed_seconds)}",
        f"Середня швидкість: {result.average_seconds_per_network:.1f} с/мережу",
    ]
    if result.was_stopped:
        lines.append(f"Заплановано до перевірки: {total_planned}")
    if skipped_open:
        lines.append(f"Пропущено відкритих мереж: {skipped_open}")
    if skipped_unselected:
        lines.append(f"Пропущено знятих галочок: {skipped_unselected}")

    if result.successful:
        lines.extend(["", "Успішно підключено:"])
        lines.extend(_format_success_line(item) for item in result.successful)

    if result.failed:
        lines.extend(["", "Не вдалося підключитися:"])
        lines.extend(f"  ✗ {item.ssid}" for item in result.failed)

    return "\n".join(lines)


def _format_test_summary(
    result: TestAllResult,
    skipped_open: int,
    *,
    total_planned: int,
) -> str:
    return _format_test_summary_short(result, total_planned=total_planned)


def _format_active_test_line(progress: TestAllProgress) -> str:
    password_hint = ""
    if progress.is_active and progress.current_password:
        if progress.password_total > 1:
            password_hint = (
                f" · пароль {progress.password_current}/{progress.password_total}: "
                f"{progress.current_password}"
            )
        else:
            password_hint = f" · {progress.current_password}"
    return (
        f"→ Перевірка {progress.current}/{progress.total}: {progress.ssid}"
        f"{password_hint}… · {progress.average_seconds_per_network:.1f} с/мережу"
    )


def _format_test_progress(progress: TestAllProgress) -> str:
    if progress.is_active:
        return _format_active_test_line(progress).removeprefix("→ ").strip()
    return (
        f"Тестування {progress.current}/{progress.total}: {progress.ssid}… · "
        f"{progress.average_seconds_per_network:.1f} с/мережу"
    )


def _format_test_log(progress: TestAllProgress) -> str:
    lines: list[str] = []
    for result in progress.completed:
        if result.is_connected:
            lines.append(_format_success_line(result))
        else:
            lines.append(f"  ✗ {result.ssid}")
    if progress.is_active:
        lines.append(
            f"→ Перевірка {progress.current}/{progress.total}: {progress.ssid}… · "
            f"{progress.average_seconds_per_network:.1f} с/мережу"
        )
    return "\n".join(lines) if lines else "→ Підготовка до тестування…"


def _test_log_font() -> NSFont:
    return NSFont.monospacedSystemFontOfSize_weight_(11, 0)


def _test_log_attributes(*, is_success: bool = False) -> dict:
    return {
        NSFontAttributeName: _test_log_font(),
        NSForegroundColorAttributeName: _LOG_SUCCESS if is_success else NSColor.labelColor(),
    }


def _build_test_log_attributed_string(progress: TestAllProgress) -> NSAttributedString:
    parts: list[NSAttributedString] = []
    default_attributes = _test_log_attributes()
    success_attributes = _test_log_attributes(is_success=True)

    def append_line(text: str, attributes: dict) -> None:
        if parts:
            parts.append(
                NSAttributedString.alloc().initWithString_attributes_("\n", default_attributes)
            )
        parts.append(NSAttributedString.alloc().initWithString_attributes_(text, attributes))

    if not progress.completed and not progress.is_active:
        append_line("→ Підготовка до тестування…", default_attributes)
    else:
        for result in progress.completed:
            if result.is_connected:
                append_line(_format_success_line(result), success_attributes)
            else:
                append_line(f"  ✗ {result.ssid}", default_attributes)
        if progress.is_active:
            append_line(_format_active_test_line(progress), default_attributes)

    combined = NSMutableAttributedString.alloc().initWithAttributedString_(parts[0])
    for part in parts[1:]:
        combined.appendAttributedString_(part)
    return combined


def _format_test_successes(successful: list[JoinResult]) -> str:
    if not successful:
        return ""
    return "\n".join(_format_success_line(item) for item in successful)


def _run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def _label(text: str, frame: tuple[float, float, float, float]) -> NSTextField:
    field = NSTextField.alloc().initWithFrame_(NSMakeRect(*frame))
    field.setStringValue_(text)
    field.setBezeled_(False)
    field.setDrawsBackground_(False)
    field.setEditable_(False)
    field.setSelectable_(False)
    return field


def _colored_button(
    frame: tuple[float, float, float, float],
    title: str,
    background: NSColor,
    *,
    text_color: NSColor | None = None,
) -> NSButton:
    button = NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
    button.setBordered_(False)
    button.setWantsLayer_(True)
    layer = button.layer()
    layer.setBackgroundColor_(background.CGColor())
    layer.setCornerRadius_(6.0)

    label_color = text_color or NSColor.whiteColor()
    attributes = {
        NSForegroundColorAttributeName: label_color,
        NSFontAttributeName: NSFont.systemFontOfSize_weight_(13, -0.1),
    }
    button.setAttributedTitle_(
        NSAttributedString.alloc().initWithString_attributes_(title, attributes)
    )
    return button


def _set_button_enabled(button: NSButton, enabled: bool) -> None:
    button.setEnabled_(enabled)
    button.setAlphaValue_(1.0 if enabled else 0.45)


def _make_password_field(secure: bool, *, y: float = _PASSWORD_Y_NORMAL) -> NSTextField | NSSecureTextField:
    if secure:
        field = NSSecureTextField.alloc().initWithFrame_(NSMakeRect(*_password_field_frame(y)))
    else:
        field = NSTextField.alloc().initWithFrame_(NSMakeRect(*_password_field_frame(y)))
    field.setAutoresizingMask_(2)
    field.setEditable_(True)
    field.setSelectable_(True)
    field.setEnabled_(True)
    return field


def _add_menu_item(
    menu: NSMenu,
    title: str,
    action: str,
    key: str = "",
) -> NSMenuItem:
    item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, key)
    menu.addItem_(item)
    return item


def _setup_application_menu(app: NSApplication) -> None:
    app_name = "Wi‑Fi Connect"
    main_menu = NSMenu.alloc().init()

    app_menu_item = NSMenuItem.alloc().init()
    main_menu.addItem_(app_menu_item)
    app_menu = NSMenu.alloc().init()
    app_menu_item.setSubmenu_(app_menu)

    _add_menu_item(app_menu, f"About {app_name}", "orderFrontStandardAboutPanel:")
    app_menu.addItem_(NSMenuItem.separatorItem())
    _add_menu_item(app_menu, f"Hide {app_name}", "hide:", "h")
    hide_others = _add_menu_item(app_menu, "Hide Others", "hideOtherApplications:", "h")
    hide_others.setKeyEquivalentModifierMask_(NSEventModifierFlagCommand | NSEventModifierFlagOption)
    _add_menu_item(app_menu, "Show All", "unhideAllApplications:", "")
    app_menu.addItem_(NSMenuItem.separatorItem())
    _add_menu_item(app_menu, f"Quit {app_name}", "terminate:", "q")

    edit_menu_item = NSMenuItem.alloc().init()
    edit_menu_item.setTitle_("Edit")
    main_menu.addItem_(edit_menu_item)
    edit_menu = NSMenu.alloc().initWithTitle_("Edit")
    edit_menu_item.setSubmenu_(edit_menu)

    _add_menu_item(edit_menu, "Undo", "undo:", "z")
    redo_item = _add_menu_item(edit_menu, "Redo", "redo:", "Z")
    redo_item.setKeyEquivalentModifierMask_(NSEventModifierFlagCommand | NSEventModifierFlagShift)
    edit_menu.addItem_(NSMenuItem.separatorItem())
    _add_menu_item(edit_menu, "Cut", "cut:", "x")
    _add_menu_item(edit_menu, "Copy", "copy:", "c")
    _add_menu_item(edit_menu, "Paste", "paste:", "v")
    edit_menu.addItem_(NSMenuItem.separatorItem())
    _add_menu_item(edit_menu, "Select All", "selectAll:", "a")

    app.setMainMenu_(main_menu)


class NetworkTableSource(NSObject):
    app_delegate: "WifiConnectDelegate"

    def numberOfRowsInTableView_(self, _table: NSTableView) -> int:
        return len(self.app_delegate.networks)

    def tableView_objectValueForTableColumn_row_(
        self,
        _table: NSTableView,
        column: NSTableColumn,
        row: int,
    ) -> str:
        network = self.app_delegate.networks[row]
        ident = str(column.identifier())
        if ident == "test":
            return (
                1
                if self.app_delegate.isNetworkSelected(row)
                else 0
            )
        if ident == "ssid":
            suffix = "  (поточна)" if network.is_current else ""
            return f"{network.ssid}{suffix}"
        if ident == "security":
            return _SECURITY_LABELS[network.security]
        if ident == "signal":
            if network.rssi_dbm is None:
                return "—"
            return f"{network.rssi_dbm} dBm"
        return ""

    def tableView_setObjectValue_forTableColumn_row_(
        self,
        _table: NSTableView,
        value: object,
        column: NSTableColumn,
        row: int,
    ) -> None:
        if str(column.identifier()) != "test":
            return
        if self.app_delegate.is_reloading_table:
            return
        self.app_delegate.setNetworkSelected(row, bool(value))
        self.app_delegate.updateSelectAllHeaderState()

    def tableView_didClickTableColumn_(self, _table: NSTableView, column: NSTableColumn) -> None:
        if str(column.identifier()) != "test":
            return
        if self.app_delegate.is_testing_all:
            return
        self.app_delegate.setAllNetworksSelected(
            not self.app_delegate.areAllNetworksSelected()
        )

    def tableView_shouldEditTableColumn_row_(
        self,
        _table: NSTableView,
        column: NSTableColumn,
        _row: int,
    ) -> bool:
        if self.app_delegate.is_testing_all:
            return False
        return str(column.identifier()) == "test"

    def tableViewSelectionDidChange_(self, _notification: object) -> None:
        self.app_delegate.updateSelectionStatus()


class WifiConnectDelegate(NSObject):
    window: NSWindow
    table: NSTableView
    table_source: NetworkTableSource
    network_scroll: NSScrollView
    password_label: NSTextField
    test_common_passwords_checkbox: NSButton
    test_common_passwords_label: NSTextField
    view_common_passwords_button: NSButton
    common_passwords_window: NSWindow | None
    common_passwords_text: NSTextView
    password_field: NSTextField | NSSecureTextField
    toggle_password_button: NSButton
    status_field: NSTextField
    test_success_scroll: NSScrollView
    test_success_text: NSTextView
    refresh_button: NSButton
    test_all_button: NSButton
    stop_test_button: NSButton
    location_button: NSButton
    connect_button: NSButton
    report_window: NSWindow | None
    report_text: NSTextView
    location: LocationController
    networks: list[WifiNetwork]
    network_checked: dict[str, bool]
    is_testing_all: bool
    is_password_visible: bool
    stop_test_event: threading.Event
    is_refreshing: bool
    is_reloading_table: bool
    _preserve_status_after_refresh: str | None
    _selection_snapshot: dict[str, bool] | None

    def applicationDidFinishLaunching_(self, _notification: object) -> None:
        self.networks = []
        self.network_checked = {}
        self.is_testing_all = False
        self.is_password_visible = False
        self.is_refreshing = False
        self.is_reloading_table = False
        self._preserve_status_after_refresh = None
        self._selection_snapshot = None
        self.report_window = None
        self.common_passwords_window = None
        self.stop_test_event = threading.Event()
        try:
            self._build_window()
            self._show_window()
            self.performSelector_withObject_afterDelay_("_finishLaunchSetup:", None, 0.05)
        except Exception as error:
            self._show_launch_error(str(error))

    def _finishLaunchSetup_(self, _sender: object) -> None:
        try:
            self.location = LocationController.alloc().init()
            self.location.on_change = self.onLocationChange
            self.refresh_(None)
            self.location.requestAccess()
        except Exception as error:
            self._show_launch_error(str(error))

    @objc.python_method
    def _show_launch_error(self, message: str) -> None:
        if not hasattr(self, "window"):
            self._build_window()
        self._show_window()
        self.setStatus_(f"Помилка запуску: {message}")
        print(f"wifi-connect launch error: {message}", flush=True)

    @objc.python_method
    def _show_window(self) -> None:
        if not hasattr(self, "window"):
            return
        self.window.makeKeyAndOrderFront_(None)
        self.window.orderFrontRegardless()
        NSApp.activateIgnoringOtherApps_(True)

    def applicationShouldHandleReopen_hasVisibleWindows_(  # noqa: N802
        self,
        _app: object,
        _has_visible_windows: bool,
    ) -> bool:
        self._show_window()
        return True

    def windowShouldClose_(self, _sender: object) -> bool:
        return True

    def applicationShouldTerminateAfterLastWindowClosed_(self, _app: object) -> bool:
        return False

    def _build_window(self) -> None:
        style = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskMiniaturizable
            | NSWindowStyleMaskResizable
        )
        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 620, 480),
            style,
            NSBackingStoreBuffered,
            False,
        )
        self.window.setTitle_("Wi‑Fi Connect")
        self.window.setMinSize_((480, 360))
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        self.window.center()

        content: NSView = self.window.contentView()
        content.addSubview_(_label("Доступні мережі", (20, 440, 300, 22)))

        self.table = NSTableView.alloc().initWithFrame_(NSMakeRect(0, 0, 580, 260))
        self.table.setAllowsMultipleSelection_(False)
        self.table.setAllowsEmptySelection_(True)

        test_column = NSTableColumn.alloc().initWithIdentifier_("test")
        header_cell = NSButtonCell.alloc().init()
        header_cell.setButtonType_(3)
        header_cell.setTitle_("")
        header_cell.setAllowsMixedState_(True)
        header_cell.setState_(1)
        test_column.setHeaderCell_(header_cell)
        test_column.setWidth_(36)
        test_column.setMinWidth_(36)
        test_column.setMaxWidth_(36)
        test_cell = NSButtonCell.alloc().init()
        test_cell.setButtonType_(3)
        test_cell.setTitle_("")
        test_column.setDataCell_(test_cell)
        self.table.addTableColumn_(test_column)

        for ident, title, width in (
            ("ssid", "Мережа", 254),
            ("security", "Захист", 100),
            ("signal", "Сигнал", 80),
        ):
            column = NSTableColumn.alloc().initWithIdentifier_(ident)
            column.headerCell().setStringValue_(title)
            column.setWidth_(width)
            column.setMinWidth_(70)
            self.table.addTableColumn_(column)

        self.table_source = NetworkTableSource.alloc().init()
        self.table_source.app_delegate = self
        self.table.setDataSource_(self.table_source)
        self.table.setDelegate_(self.table_source)

        scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(20, _TABLE_Y_NORMAL, 580, _TABLE_H_NORMAL)
        )
        scroll.setDocumentView_(self.table)
        scroll.setHasVerticalScroller_(True)
        scroll.setBorderType_(1)
        scroll.setAutoresizingMask_(18)
        content.addSubview_(scroll)
        self.network_scroll = scroll

        self.password_label = _label("Пароль", (20, _PASSWORD_LABEL_Y_NORMAL, 70, 22))
        content.addSubview_(self.password_label)

        self.test_common_passwords_checkbox = _make_checkbox_control(
            _common_passwords_checkbox_frame(_PASSWORD_LABEL_Y_NORMAL),
        )
        content.addSubview_(self.test_common_passwords_checkbox)

        self.test_common_passwords_label = _label(
            "Типові паролі",
            _common_passwords_caption_frame(_PASSWORD_LABEL_Y_NORMAL),
        )
        content.addSubview_(self.test_common_passwords_label)

        self.view_common_passwords_button = _make_inline_button(
            _common_passwords_list_button_frame(_PASSWORD_LABEL_Y_NORMAL),
            "показати список",
            self,
            "showCommonPasswords:",
        )
        content.addSubview_(self.view_common_passwords_button)

        self.password_field = _make_password_field(secure=True)
        self.password_field.setStringValue_(default_password())
        content.addSubview_(self.password_field)

        self.toggle_password_button = _colored_button(
            _toggle_password_frame(),
            "Показати",
            _BTN_TOGGLE,
        )
        self.toggle_password_button.setTarget_(self)
        self.toggle_password_button.setAction_("togglePasswordVisibility:")
        content.addSubview_(self.toggle_password_button)

        self.refresh_button = _colored_button(
            (20, 48, 110, 32),
            "Оновити список",
            _BTN_REFRESH,
            text_color=NSColor.whiteColor(),
        )
        self.refresh_button.setTarget_(self)
        self.refresh_button.setAction_("refresh:")
        content.addSubview_(self.refresh_button)

        self.test_all_button = _colored_button(
            (135, 48, 140, 32),
            "Протестувати всі",
            _BTN_TEST,
        )
        self.test_all_button.setTarget_(self)
        self.test_all_button.setAction_("testAll:")
        content.addSubview_(self.test_all_button)

        self.stop_test_button = _colored_button(
            (135, 48, 140, 32),
            "Зупинити тест",
            _BTN_STOP,
        )
        self.stop_test_button.setTarget_(self)
        self.stop_test_button.setAction_("stopTest:")
        self.stop_test_button.setHidden_(True)
        content.addSubview_(self.stop_test_button)

        self.location_button = _colored_button(
            (280, 48, 150, 32),
            "Дозволити локацію",
            _BTN_LOCATION,
        )
        self.location_button.setTarget_(self)
        self.location_button.setAction_("openLocationSettings:")
        content.addSubview_(self.location_button)

        self.connect_button = _colored_button(
            (435, 48, 165, 32),
            "Підключити",
            _BTN_CONNECT,
        )
        self.connect_button.setTarget_(self)
        self.connect_button.setAction_("connect:")
        self.connect_button.setKeyEquivalent_("\r")
        self.connect_button.setAutoresizingMask_(1)
        content.addSubview_(self.connect_button)

        self.status_field = NSTextField.alloc().initWithFrame_(NSMakeRect(*_STATUS_FRAME_NORMAL))
        self.status_field.setStringValue_("Сканування мереж…")
        self.status_field.setBezeled_(False)
        self.status_field.setDrawsBackground_(False)
        self.status_field.setEditable_(False)
        self.status_field.setSelectable_(True)
        self.status_field.setUsesSingleLineMode_(True)
        self.status_field.setMaximumNumberOfLines_(1)
        self.status_field.setAutoresizingMask_(2)
        content.addSubview_(self.status_field)

        self.test_success_scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(*_SUCCESS_LOG_FRAME))
        self.test_success_scroll.setHasVerticalScroller_(True)
        self.test_success_scroll.setBorderType_(1)
        self.test_success_scroll.setDrawsBackground_(True)
        self.test_success_scroll.setBackgroundColor_(NSColor.textBackgroundColor())
        self.test_success_scroll.setHidden_(True)
        self.test_success_text = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 560, 50))
        self.test_success_text.setEditable_(False)
        self.test_success_text.setSelectable_(True)
        self.test_success_text.setRichText_(True)
        self.test_success_text.setDrawsBackground_(True)
        self.test_success_text.setBackgroundColor_(NSColor.textBackgroundColor())
        self.test_success_text.setTextColor_(NSColor.labelColor())
        self.test_success_text.setFont_(NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        self.test_success_text.setTextContainerInset_((4, 8))
        self.test_success_scroll.setDocumentView_(self.test_success_text)
        content.addSubview_(self.test_success_scroll)

    @objc.python_method
    def _move_button_y_(self, button: NSButton, y: float) -> None:
        frame = button.frame()
        button.setFrame_(NSMakeRect(frame.origin.x, y, frame.size.width, frame.size.height))

    @objc.python_method
    def _set_testing_layout(self, *, is_testing: bool) -> None:
        button_y = _BUTTON_Y_TESTING if is_testing else _BUTTON_Y_NORMAL
        password_y = _PASSWORD_Y_TESTING if is_testing else _PASSWORD_Y_NORMAL
        label_y = _PASSWORD_LABEL_Y_TESTING if is_testing else _PASSWORD_LABEL_Y_NORMAL
        table_y = _TABLE_Y_TESTING if is_testing else _TABLE_Y_NORMAL
        table_h = _TABLE_H_TESTING if is_testing else _TABLE_H_NORMAL

        for button in (
            self.refresh_button,
            self.test_all_button,
            self.stop_test_button,
            self.location_button,
            self.connect_button,
        ):
            self._move_button_y_(button, button_y)

        password_frame = self.password_field.frame()
        self.password_field.setFrame_(
            NSMakeRect(password_frame.origin.x, password_y, password_frame.size.width, password_frame.size.height)
        )
        toggle_frame = self.toggle_password_button.frame()
        self.toggle_password_button.setFrame_(
            NSMakeRect(toggle_frame.origin.x, password_y, toggle_frame.size.width, toggle_frame.size.height)
        )
        label_frame = self.password_label.frame()
        self.password_label.setFrame_(
            NSMakeRect(label_frame.origin.x, label_y, label_frame.size.width, label_frame.size.height)
        )
        self.test_common_passwords_checkbox.setFrame_(
            NSMakeRect(*_common_passwords_checkbox_frame(label_y))
        )
        self.test_common_passwords_label.setFrame_(
            NSMakeRect(*_common_passwords_caption_frame(label_y))
        )
        self.view_common_passwords_button.setFrame_(
            NSMakeRect(*_common_passwords_list_button_frame(label_y))
        )
        self.network_scroll.setFrame_(NSMakeRect(20, table_y, 580, table_h))
        self.test_success_scroll.setHidden_(not is_testing)
        if not is_testing:
            self.test_success_text.setString_("")

        self.status_field.setFrame_(NSMakeRect(*_STATUS_FRAME_NORMAL))
        self.status_field.setUsesSingleLineMode_(True)
        self.status_field.setMaximumNumberOfLines_(1)

    def applyTestProgress_(self, _sender: object) -> None:
        progress = getattr(self, "_pending_test_progress", None)
        if progress is not None:
            self.setStatus_(_format_test_progress(progress))
            self.test_success_text.textStorage().setAttributedString_(
                _build_test_log_attributed_string(progress)
            )
            text_length = len(self.test_success_text.string())
            if text_length:
                self.test_success_text.scrollRangeToVisible_(
                    NSMakeRange(max(text_length - 1, 0), 1)
                )

    @objc.python_method
    def selectedNetwork(self) -> WifiNetwork | None:
        row = int(self.table.selectedRow())
        if row < 0 or row >= len(self.networks):
            return None
        return self.networks[row]

    @objc.python_method
    def isNetworkChecked(self, ssid: str) -> bool:
        return self.network_checked.get(ssid, False)

    @objc.python_method
    def snapshotNetworkSelection(self) -> dict[str, bool]:
        return {network.ssid: self.isNetworkChecked(network.ssid) for network in self.networks}

    @objc.python_method
    def restoreNetworkSelection(self, snapshot: dict[str, bool]) -> None:
        self.network_checked = {
            network.ssid: snapshot.get(network.ssid, False) for network in self.networks
        }
        self.updateSelectAllHeaderState()

    @objc.python_method
    def syncNetworkSelection(self) -> None:
        previous = self.network_checked
        if not previous:
            self.network_checked = {network.ssid: True for network in self.networks}
        else:
            self.network_checked = {
                network.ssid: previous.get(network.ssid, False) for network in self.networks
            }
        self.updateSelectAllHeaderState()

    @objc.python_method
    def reloadNetworkTable(self) -> None:
        self.is_reloading_table = True
        self.table.reloadData()
        self.is_reloading_table = False

    @objc.python_method
    def areAllNetworksSelected(self) -> bool:
        if not self.networks:
            return False
        return all(self.isNetworkChecked(network.ssid) for network in self.networks)

    @objc.python_method
    def setAllNetworksSelected(self, is_selected: bool) -> None:
        for network in self.networks:
            self.network_checked[network.ssid] = is_selected
        self.reloadNetworkTable()
        self.updateSelectAllHeaderState()
        self.updateSelectionStatus()

    @objc.python_method
    def updateSelectAllHeaderState(self) -> None:
        column = self.table.tableColumnWithIdentifier_("test")
        if column is None:
            return
        header_cell = column.headerCell()
        selected_count = self.selectedNetworkCount()
        total_count = len(self.networks)
        if total_count == 0 or selected_count == 0:
            header_cell.setState_(0)
        elif selected_count == total_count:
            header_cell.setState_(1)
        else:
            header_cell.setState_(-1)
        header_view = self.table.headerView()
        if header_view is not None:
            header_view.setNeedsDisplay_(True)

    @objc.python_method
    def isNetworkSelected(self, row: int) -> bool:
        if row < 0 or row >= len(self.networks):
            return False
        return self.isNetworkChecked(self.networks[row].ssid)

    @objc.python_method
    def setNetworkSelected(self, row: int, is_selected: bool) -> None:
        if row < 0 or row >= len(self.networks):
            return
        self.network_checked[self.networks[row].ssid] = is_selected
        self.updateSelectAllHeaderState()
        self.updateSelectionStatus()

    @objc.python_method
    def selectedNetworkCount(self) -> int:
        return sum(
            1
            for network in self.networks
            if self.isNetworkChecked(network.ssid)
        )

    @objc.python_method
    def updateSelectionStatus(self) -> None:
        selected_count = self.selectedNetworkCount()
        total_count = len(self.networks)
        network = self.selectedNetwork()
        if network is not None:
            self.status_field.setStringValue_(
                f"Обрано для тесту: {selected_count}/{total_count} · рядок: {network.ssid}"
            )
            return
        self.status_field.setStringValue_(
            f"Обрано для тесту: {selected_count}/{total_count}"
        )

    @objc.python_method
    def onLocationChange(self, _status: int) -> None:
        self.refresh_(None)

    def openLocationSettings_(self, _sender: object) -> None:
        self.location.requestAccess()
        url = NSURL.URLWithString_(_LOCATION_SETTINGS)
        if url is not None:
            NSWorkspace.sharedWorkspace().openURL_(url)

    def refresh_(self, _sender: object) -> None:
        if self.is_refreshing or self.is_testing_all:
            return
        self.is_refreshing = True
        if not getattr(self, "_preserve_status_after_refresh", None):
            self.setStatus_("Сканування мереж…")
        _set_button_enabled(self.refresh_button, False)
        delegate = self

        def worker() -> None:
            try:
                networks, hint = asyncio.run(list_visible_networks())
                delegate._refresh_error = None
                delegate._refresh_networks = networks
                delegate._refresh_hint = hint
            except Exception as error:
                delegate._refresh_error = error
                delegate._refresh_networks = []
                delegate._refresh_hint = None
            delegate.performSelectorOnMainThread_withObject_waitUntilDone_(
                "completeRefresh:",
                None,
                False,
            )

        threading.Thread(target=worker, daemon=True).start()

    def completeRefresh_(self, _sender: object) -> None:
        self.is_refreshing = False
        if not self.is_testing_all:
            _set_button_enabled(self.refresh_button, True)

        error = getattr(self, "_refresh_error", None)
        if error is not None:
            self.setStatus_(f"Не вдалося просканувати: {error}")
            return

        self.networks = getattr(self, "_refresh_networks", [])
        hint = getattr(self, "_refresh_hint", None)
        snapshot = getattr(self, "_selection_snapshot", None)
        if snapshot is not None:
            self.restoreNetworkSelection(snapshot)
            self._selection_snapshot = None
        else:
            self.syncNetworkSelection()
        self.reloadNetworkTable()
        self.updateSelectAllHeaderState()
        if self.networks:
            self.table.selectRowIndexes_byExtendingSelection_(
                NSIndexSet.indexSetWithIndex_(0),
                False,
            )
            preserved = getattr(self, "_preserve_status_after_refresh", None)
            if preserved:
                self.setStatus_(preserved)
                self._preserve_status_after_refresh = None
            else:
                message = (
                    f"Знайдено мереж: {len(self.networks)} · "
                    f"обрано для тесту: {self.selectedNetworkCount()}"
                )
                if hint:
                    message = f"{message}. {hint}"
                self.setStatus_(message)
                self.updateSelectionStatus()
            return

        preserved = getattr(self, "_preserve_status_after_refresh", None)
        if preserved:
            self.setStatus_(preserved)
            self._preserve_status_after_refresh = None
            return

        self.setStatus_(
            hint or "Мереж не знайдено. Перевірте Wi‑Fi і дозвіл на Геолокацію."
        )

    @objc.python_method
    def testableNetworks(self) -> list[WifiNetwork]:
        return [
            network
            for network in self.networks
            if network.security != SecurityKind.OPEN
            and self.isNetworkChecked(network.ssid)
        ]

    @objc.python_method
    def _replace_password_field(self, secure: bool) -> None:
        password = str(self.password_field.stringValue() or "")
        password_y = float(self.password_field.frame().origin.y)
        superview = self.password_field.superview()
        new_field = _make_password_field(secure, y=password_y)
        new_field.setStringValue_(password)
        superview.replaceSubview_with_(self.password_field, new_field)
        self.password_field = new_field

    def togglePasswordVisibility_(self, _sender: object) -> None:
        self.is_password_visible = not self.is_password_visible
        self._replace_password_field(secure=not self.is_password_visible)
        self.toggle_password_button.setAttributedTitle_(
            NSAttributedString.alloc().initWithString_attributes_(
                "Сховати" if self.is_password_visible else "Показати",
                {
                    NSForegroundColorAttributeName: NSColor.whiteColor(),
                    NSFontAttributeName: NSFont.systemFontOfSize_weight_(12, -0.1),
                },
            )
        )

    @objc.python_method
    def setTestingUi_(self, is_testing: bool) -> None:
        self.is_testing_all = is_testing
        self._set_testing_layout(is_testing=is_testing)
        self.test_all_button.setHidden_(is_testing)
        self.stop_test_button.setHidden_(not is_testing)
        _set_button_enabled(self.refresh_button, not is_testing)
        _set_button_enabled(self.location_button, not is_testing)
        _set_button_enabled(self.connect_button, not is_testing)
        _set_button_enabled(self.toggle_password_button, not is_testing)
        _set_button_enabled(self.test_common_passwords_checkbox, not is_testing)
        _set_button_enabled(self.stop_test_button, is_testing)
        self.password_field.setEnabled_(not is_testing)

    @objc.python_method
    def setActionButtonsEnabled_(self, enabled: bool) -> None:
        if not enabled:
            return
        self.is_testing_all = False
        self._set_testing_layout(is_testing=False)
        self.test_all_button.setHidden_(False)
        self.stop_test_button.setHidden_(True)
        for button in (
            self.refresh_button,
            self.test_all_button,
            self.location_button,
            self.connect_button,
            self.toggle_password_button,
            self.test_common_passwords_checkbox,
        ):
            _set_button_enabled(button, True)
        self.password_field.setEnabled_(True)

    def setStatus_(self, message: object) -> None:
        self.status_field.setStringValue_(str(message))

    @objc.python_method
    def _ensure_common_passwords_window(self) -> None:
        if getattr(self, "common_passwords_window", None) is not None:
            return

        style = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskMiniaturizable
            | NSWindowStyleMaskResizable
        )
        self.common_passwords_window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 320, 260),
            style,
            NSBackingStoreBuffered,
            False,
        )
        self.common_passwords_window.setTitle_("Типові паролі")
        self.common_passwords_window.setMinSize_((260, 180))
        self.common_passwords_window.setReleasedWhenClosed_(False)
        self.common_passwords_window.setDelegate_(self)

        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(0, 0, 320, 260))
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(False)
        scroll.setBorderType_(1)
        scroll.setAutoresizingMask_(18)

        self.common_passwords_text = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 300, 240))
        self.common_passwords_text.setEditable_(False)
        self.common_passwords_text.setSelectable_(True)
        self.common_passwords_text.setRichText_(False)
        self.common_passwords_text.setDrawsBackground_(True)
        self.common_passwords_text.setBackgroundColor_(NSColor.textBackgroundColor())
        self.common_passwords_text.setTextColor_(NSColor.labelColor())
        self.common_passwords_text.setFont_(NSFont.monospacedSystemFontOfSize_weight_(12, 0))
        self.common_passwords_text.setTextContainerInset_((12, 12))
        scroll.setDocumentView_(self.common_passwords_text)
        self.common_passwords_window.setContentView_(scroll)

    def showCommonPasswords_(self, _sender: object) -> None:
        self._ensure_common_passwords_window()
        reload_password_config()
        text = _format_common_passwords_list()
        self.common_passwords_text.setString_(text)
        self.common_passwords_text.setSelectedRange_(NSMakeRange(0, len(text)))
        self.common_passwords_window.center()
        self.common_passwords_window.makeKeyAndOrderFront_(None)
        NSApp.activateIgnoringOtherApps_(True)

    @objc.python_method
    def _ensure_report_window(self) -> None:
        if getattr(self, "report_window", None) is not None:
            return

        style = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskMiniaturizable
            | NSWindowStyleMaskResizable
        )
        self.report_window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 560, 420),
            style,
            NSBackingStoreBuffered,
            False,
        )
        self.report_window.setTitle_("Звіт про тестування")
        self.report_window.setMinSize_((420, 280))
        self.report_window.setReleasedWhenClosed_(False)
        self.report_window.setDelegate_(self)

        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(0, 0, 560, 420))
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(False)
        scroll.setBorderType_(1)
        scroll.setAutoresizingMask_(18)

        self.report_text = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 540, 400))
        self.report_text.setEditable_(False)
        self.report_text.setSelectable_(True)
        self.report_text.setRichText_(False)
        self.report_text.setFont_(NSFont.monospacedSystemFontOfSize_weight_(12, 0))
        self.report_text.setTextContainerInset_((12, 12))
        scroll.setDocumentView_(self.report_text)
        self.report_window.setContentView_(scroll)

    @objc.python_method
    def showTestReport_(self, report: object) -> None:
        self._ensure_report_window()
        report_text = str(report)
        self.report_text.setString_(report_text)
        self.report_text.setSelectedRange_(NSMakeRange(0, len(report_text)))
        self.report_window.center()
        self.report_window.makeKeyAndOrderFront_(None)
        self.report_window.makeFirstResponder_(self.report_text)
        NSApp.activateIgnoringOtherApps_(True)

    def finishTestAll_(self, _sender: object) -> None:
        self.stop_test_event.clear()
        self.setActionButtonsEnabled_(True)

        error = getattr(self, "_pending_test_error", None)
        if error is not None:
            self._pending_test_error = None
            self._selection_snapshot = None
            self.setStatus_(f"Помилка: {error}")
            return

        summary = getattr(self, "_pending_test_summary", None)
        report = getattr(self, "_pending_test_report", None)
        self._pending_test_summary = None
        self._pending_test_report = None

        if summary:
            self._preserve_status_after_refresh = str(summary)
            self.setStatus_(summary)
        if report:
            self.showTestReport_(report)

        self.refresh_(None)

    def stopTest_(self, _sender: object) -> None:
        if self.is_testing_all:
            self.stop_test_event.set()
            self.setStatus_("Зупинка тесту…")

    def testAll_(self, _sender: object) -> None:
        if self.is_testing_all:
            return

        password = str(self.password_field.stringValue() or "")
        include_common = bool(self.test_common_passwords_checkbox.state())
        reload_password_config()
        passwords = build_test_passwords(password, include_common=include_common)
        if not passwords:
            if include_common:
                self.setStatus_("Немає паролів для перевірки.")
            else:
                self.setStatus_("Введіть пароль для перевірки.")
            return

        for candidate in passwords:
            try:
                JoinRequest(ssid="validation-placeholder", password=candidate)
            except ValidationError as error:
                self.setStatus_(error.errors()[0]["msg"])
                return

        testable = self.testableNetworks()
        if not testable:
            self.setStatus_("Оберіть хоча б одну захищену мережу для перевірки.")
            return

        skipped_open = sum(
            1
            for network in self.networks
            if network.security == SecurityKind.OPEN
            and self.isNetworkChecked(network.ssid)
        )
        skipped_unselected = sum(
            1
            for network in self.networks
            if network.security != SecurityKind.OPEN
            and not self.isNetworkChecked(network.ssid)
        )
        self._selection_snapshot = self.snapshotNetworkSelection()
        self.stop_test_event.clear()
        self.setTestingUi_(True)
        self.test_success_text.setString_("→ Підготовка до тестування…")
        self.setStatus_(f"Тестування 0/{len(testable)}…")

        delegate = self
        total_planned = len(testable)

        def worker() -> None:
            def on_progress(progress: TestAllProgress) -> None:
                delegate._pending_test_progress = progress
                delegate.performSelectorOnMainThread_withObject_waitUntilDone_(
                    "applyTestProgress:",
                    None,
                    False,
                )

            try:
                result = asyncio.run(
                    test_all_networks(
                        testable,
                        passwords,
                        on_progress=on_progress,
                        should_stop=delegate.stop_test_event.is_set,
                    )
                )
            except Exception as error:
                delegate._pending_test_error = str(error)
                delegate._pending_test_summary = None
                delegate._pending_test_report = None
                delegate.performSelectorOnMainThread_withObject_waitUntilDone_(
                    "finishTestAll:",
                    None,
                    False,
                )
                return

            delegate._pending_test_error = None
            delegate._pending_test_summary = _format_test_summary_short(
                result,
                total_planned=total_planned,
            )
            delegate._pending_test_report = _format_test_report(
                result,
                total_planned=total_planned,
                skipped_open=skipped_open,
                skipped_unselected=skipped_unselected,
            )
            delegate.performSelectorOnMainThread_withObject_waitUntilDone_(
                "finishTestAll:",
                None,
                False,
            )

        threading.Thread(target=worker, daemon=True).start()

    def connect_(self, _sender: object) -> None:
        network = self.selectedNetwork()
        if network is None:
            self.status_field.setStringValue_("Оберіть мережу зі списку.")
            return

        password = str(self.password_field.stringValue() or "")
        try:
            request = JoinRequest(ssid=network.ssid, password=password)
        except ValidationError as error:
            self.status_field.setStringValue_(error.errors()[0]["msg"])
            return

        self.status_field.setStringValue_(f"Підключення до {request.ssid}…")
        try:
            result = _run(join_network(request))
        except Exception as error:
            self.status_field.setStringValue_(f"Помилка: {error}")
            return

        self.status_field.setStringValue_(result.message)


def run_app() -> None:
    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
    _setup_application_menu(app)
    delegate = WifiConnectDelegate.alloc().init()
    app.setDelegate_(delegate)
    app.activateIgnoringOtherApps_(True)
    app.run()
