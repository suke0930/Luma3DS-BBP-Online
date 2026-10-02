import re

from _support import ROOT, read_c


MAIN = ROOT / "sysmodules/rosalina/source/main.c"
ROOT_MENU = ROOT / "sysmodules/rosalina/source/menus.c"
MENU = ROOT / "sysmodules/rosalina/source/menus/bbp_online.c"
MENU_DRAW = ROOT / "sysmodules/rosalina/source/menu.c"


def test_bbp_config_precedes_uds_service_and_no_development_threads_start():
    main = read_c(MAIN)
    assert '"plg:UDS"' not in main
    load = re.search(r"\bUdsRedirect_LoadConfig\s*\(", main)
    uds_service = re.search(r"\bUdsService_Start\s*\(", main)
    relay_thread = re.search(r"\bUdsRedirect_CreateRelayThread\s*\(", main)
    service_manager = re.search(r"\bServiceManager_Run\s*\(", main)
    assert load and uds_service and relay_thread and service_manager
    assert load.start() < uds_service.start() < service_manager.start()
    assert relay_thread.start() < service_manager.start()
    for disabled_thread in (
        "UdsRedirect_CreateLogThread",
        "UdsRedirect_CreateBeaconThread",
        "SDHost_CreateThread",
    ):
        assert re.search(r"\b" + disabled_thread + r"\s*\(", main) is None


def test_bbp_menu_keeps_play_controls_without_development_services():
    root_menu = read_c(ROOT_MENU)
    menu = read_c(MENU)
    menu_draw = read_c(MENU_DRAW)
    assert re.search(r'#\s*include\s*"menus/bbp_online\.h"', root_menu)
    assert re.search(
        r'\{\s*"BBP Online\.\.\."\s*,\s*MENU\s*,\s*\.menu\s*=\s*&bbpOnlineMenu\s*\}',
        root_menu,
    )

    initializer = re.search(r"\bMenu\s+bbpOnlineMenu\s*=\s*\{(.*?)\};", menu, re.S)
    assert initializer is not None
    entries = initializer.group(1)
    expected_entries = (
        r'\{\s*"Status"\s*,\s*METHOD\s*,\s*\.method\s*=\s*showStatus\s*\}',
        r'\{\s*relayTitle\s*,\s*METHOD\s*,\s*\.method\s*=\s*toggleRelay\s*\}',
        r'\{\s*"Relay server\.\.\."\s*,\s*METHOD\s*,\s*\.method\s*=\s*showServers\s*\}',
        r'\{\s*channelTitle\s*,\s*METHOD\s*,\s*\.method\s*=\s*editChannel\s*\}',
        r'\{\s*pinTitle\s*,\s*METHOD\s*,\s*\.method\s*=\s*editPin\s*\}',
    )
    assert len(re.findall(r"\{\s*(?:\"|relayTitle|channelTitle|pinTitle)", entries)) == 5
    for pattern in expected_entries:
        assert re.search(pattern, entries), pattern

    menu_draw_body = re.search(
        r"static\s+void\s+menuDraw\s*\([^{}]*\)\s*\{(.*?)\n\}",
        menu_draw,
        re.S,
    )
    assert menu_draw_body is not None
    assert re.search(r"BbpOnline_UpdateMenu\s*\(\s*bbpOverlay\s*\)", menu_draw_body.group(1))

    for excluded in (
        "UDS trace", "Freeze dump", "SD file host", "Receive boot.firm",
        "Diagnostics", "toggleDiagnostics",
    ):
        assert excluded not in menu


if __name__ == "__main__":
    test_bbp_config_precedes_uds_service_and_no_development_threads_start()
    test_bbp_menu_keeps_play_controls_without_development_services()
