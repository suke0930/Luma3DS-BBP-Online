import ctypes
import re
import subprocess
import tempfile
from pathlib import Path

from _support import ROOT, function_body, read_c


INCLUDE = ROOT / "sysmodules/rosalina/include"
MESSAGE_SOURCE = ROOT / "sysmodules/rosalina/source/bbp_relay_message.c"
FMT_SOURCE = ROOT / "sysmodules/rosalina/source/fmt.c"
VIEW_HEADER = INCLUDE / "menus/bbp_online_view.h"
MENU_SOURCE = ROOT / "sysmodules/rosalina/source/menus/bbp_online.c"
MENU_DRAW_SOURCE = ROOT / "sysmodules/rosalina/source/menu.c"


class ViewState(ctypes.Structure):
    _fields_ = [
        ("enabled", ctypes.c_bool),
        ("connected", ctypes.c_bool),
        ("connecting", ctypes.c_bool),
        ("channel", ctypes.c_uint8),
        ("pin", ctypes.c_uint16),
        ("latency_valid", ctypes.c_bool),
        ("connect_ms", ctypes.c_uint32),
        ("relay_rtt_ms", ctypes.c_uint32),
        ("status_valid", ctypes.c_bool),
        ("online", ctypes.c_uint16),
        ("in_game", ctypes.c_uint16),
        ("rooms", ctypes.c_uint8 * 5),
    ]


class ViewText(ctypes.Structure):
    _fields_ = [
        ("relay_title", ctypes.c_char * 16),
        ("channel_title", ctypes.c_char * 32),
        ("passphrase_title", ctypes.c_char * 32),
        ("overlay", ctypes.c_char * 32),
        ("relay_status", ctypes.c_char * 12),
        ("latency", ctypes.c_char * 96),
        ("statistics", ctypes.c_char * 128),
    ]


class GuardedViewText(ctypes.Structure):
    _fields_ = [
        ("before", ctypes.c_uint8 * 16),
        ("text", ViewText),
        ("after", ctypes.c_uint8 * 16),
    ]


class Header(ctypes.Structure):
    _fields_ = [
        ("packet_type", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("token", ctypes.c_uint8 * 16),
        ("fragment_id", ctypes.c_uint32),
        ("fragment_index", ctypes.c_uint8),
        ("fragment_count", ctypes.c_uint8),
        ("logical_body_length", ctypes.c_uint16),
    ]


def _compile(directory, sources, extra_source=""):
    wrapper_path = Path(directory) / "bbp_menu_behavior.c"
    library_path = Path(directory) / "libbbp-menu-behavior.so"
    wrapper_path.write_text(extra_source, encoding="utf-8")
    subprocess.run(
        [
            "cc", "-shared", "-fPIC", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(INCLUDE), *map(str, sources), str(wrapper_path), "-o", str(library_path),
        ],
        check=True,
    )
    return ctypes.CDLL(str(library_path))


def _compile_with_luma_formatter(directory):
    stub_root = Path(directory) / "stub"
    types_header = stub_root / "3ds/types.h"
    types_header.parent.mkdir(parents=True)
    types_header.write_text(
        "#include <stdbool.h>\n"
        "#include <stdint.h>\n"
        "typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;\n"
        "typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;\n",
        encoding="utf-8",
    )
    wrapper_path = Path(directory) / "bbp_menu_luma_fmt.c"
    library_path = Path(directory) / "libbbp-menu-luma-fmt.so"
    wrapper_path.write_text(
        '#include "menus/bbp_online_view.h"\n'
        'void format_view(const BbpOnlineViewState *state, BbpOnlineViewText *text) {\n'
        '    BbpOnline_FormatView(state, text);\n'
        '}\n'
        'const char *query_reason(const char *reason, bool include_status,\n'
        '                         bool latency_valid, bool status_valid) {\n'
        '    return BbpOnline_QueryReason(reason, include_status,\n'
        '                                 latency_valid, status_valid);\n'
        '}\n',
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc", "-shared", "-fPIC", "-std=c11", "-D_GNU_SOURCE",
            "-Dsprintf=bbp_test_luma_sprintf", "-Dvsprintf=bbp_test_luma_vsprintf",
            "-Wall", "-Wextra", "-Werror", "-I", str(stub_root), "-I", str(INCLUDE),
            str(FMT_SOURCE), str(wrapper_path), "-o", str(library_path),
        ],
        check=True,
    )
    undefined_symbols = subprocess.check_output(
        ["nm", "-D", "-u", str(library_path)], text=True
    )
    assert re.search(r"\bsnprintf(?:@|$)", undefined_symbols) is None, (
        "the production view formatter must not depend on newlib snprintf; "
        f"undefined symbols were:\n{undefined_symbols}"
    )
    assert re.search(r"\bbbp_test_luma_sprintf$", subprocess.check_output(
        ["nm", "-D", str(library_path)], text=True
    ), re.M), "the host formatter test must execute Rosalina's actual fmt.c sprintf"
    return ctypes.CDLL(str(library_path))


def test_relay_overlay_keeps_menu_and_cursor_positions():
    draw_header = read_c(INCLUDE / "draw.h")
    spacing = re.search(r"#define\s+SPACING_Y\s+(\d+)", draw_header)
    assert spacing is not None
    row_spacing = int(spacing.group(1))
    draw_source = read_c(ROOT / "sysmodules/rosalina/source/draw.c")
    glyph_height = re.search(r"for\s*\(y\s*=\s*0;\s*y\s*<\s*(\d+);", draw_source)
    assert glyph_height is not None
    height = int(glyph_height.group(1))
    source = read_c(MENU_DRAW_SOURCE)
    wrapper = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned long u32;
typedef unsigned char u8;
typedef long long s64;
typedef int Result;
#define SPACING_X 6
#define SCREEN_BOT_WIDTH 320
#define SCREEN_BOT_HEIGHT 240
#define COLOR_WHITE 1
#define COLOR_TITLE 2
#define GET_VERSION_REVISION(v) ((v) & 0xFFu)
#define GET_VERSION_MINOR(v) (((v) >> 8) & 0xFFu)
#define GET_VERSION_MAJOR(v) (((v) >> 16) & 0xFFu)
typedef struct { const char *title; bool hidden; } MenuItem;
typedef struct { const char *title; MenuItem items[4]; } Menu;
static bool miniSocEnabled;
static float batteryVoltage, batteryPercentage;
static u8 batteryTemperature;
static const char *overlay;
static u32 item_y[3], cursor_y[3], selected_y, overlay_y;
static unsigned items_drawn, cursors_drawn;
static Result menuUpdateMcuInfo(void) { return 0; }
static void svcGetSystemInfo(s64 *out, u32 type, u32 parameter)
{ (void)type; *out = parameter == 0x200u; }
static void BbpOnline_UpdateMenu(char text[32]) { strcpy(text, overlay); }
static u32 menuCountItems(const Menu *menu) { (void)menu; return 4; }
static bool menuItemIsHidden(const MenuItem *item) { return item->hidden; }
static u32 socGethostid(void) { return 0; }
static u32 Draw_DrawString(u32 x, u32 y, u32 color, const char *text)
{
    (void)color;
    if (x == 30 && items_drawn < 3) item_y[items_drawn++] = y;
    if (strncmp(text, "BBP:", 4) == 0) overlay_y = y;
    return y;
}
static void Draw_DrawCharacter(u32 x, u32 y, u32 color, char character)
{
    (void)x; (void)color;
    if (cursors_drawn < 3) cursor_y[cursors_drawn++] = y;
    if (character == '>') selected_y = y;
}
static void Draw_DrawFormattedString(u32 x, u32 y, u32 color, const char *fmt, ...)
{ (void)x; (void)y; (void)color; (void)fmt; }
static void Draw_FlushFramebuffer(void) {}
"""
    wrapper += f"\n#define SPACING_Y {row_spacing}\n"
    wrapper += "static void menuDraw(Menu *menu, u32 selected) {\n"
    wrapper += function_body(source, "menuDraw") + "\n}\n"
    wrapper += r"""
void render_menu(const char *text, unsigned selected, bool show_ip)
{
    Menu menu = { "Rosalina menu", {
        { "First", false }, { "Hidden", true },
        { "Second", false }, { "Third", false }
    } };
    overlay = text;
    miniSocEnabled = show_ip;
    items_drawn = cursors_drawn = 0;
    selected_y = overlay_y = 0;
    menuDraw(&menu, selected);
}
unsigned long drawn_item_y(unsigned index) { return item_y[index]; }
unsigned long drawn_cursor_y(unsigned index) { return cursor_y[index]; }
unsigned long drawn_selected_y(void) { return selected_y; }
unsigned long drawn_overlay_y(void) { return overlay_y; }
unsigned drawn_item_count(void) { return items_drawn; }
unsigned drawn_cursor_count(void) { return cursors_drawn; }
"""
    with tempfile.TemporaryDirectory() as directory:
        library = _compile(directory, [], wrapper)
        library.render_menu.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_bool]
        for name in ("drawn_item_y", "drawn_cursor_y"):
            function = getattr(library, name)
            function.argtypes = [ctypes.c_uint]
            function.restype = ctypes.c_ulong
        for name in ("drawn_selected_y", "drawn_overlay_y"):
            getattr(library, name).restype = ctypes.c_ulong
        expected = [30 + row_spacing * i for i in range(3)]
        for text in (b"", b"BBP:NG C:1 P:0000", b"BBP:OK C:- P:9999"):
            for show_ip in (False, True):
                for selected, visible_index in ((0, 0), (2, 1), (3, 2)):
                    library.render_menu(text, selected, show_ip)
                    assert library.drawn_item_count() == 3
                    assert library.drawn_cursor_count() == 3
                    positions = [library.drawn_item_y(i) for i in range(3)]
                    assert positions == expected, f"Relay overlay shifted items: {positions}"
                    assert [library.drawn_cursor_y(i) for i in range(3)] == expected
                    assert library.drawn_selected_y() == expected[visible_index]
                    if text:
                        assert 10 + height <= library.drawn_overlay_y()
                        assert library.drawn_overlay_y() + height <= expected[0]
                    else:
                        assert library.drawn_overlay_y() == 0


def test_view_formatter_preserves_counts_and_marks_unavailable_values():
    assert VIEW_HEADER.exists(), "the menu's production formatter is not implemented yet"
    with tempfile.TemporaryDirectory() as directory:
        library = _compile_with_luma_formatter(directory)
        library.format_view.argtypes = [ctypes.POINTER(ViewState), ctypes.POINTER(ViewText)]
        library.format_view.restype = None

        state = ViewState()
        state.enabled = True
        state.connected = True
        state.channel = 4
        state.pin = 4321
        state.latency_valid = True
        state.connect_ms = 123
        state.relay_rtt_ms = 41
        state.status_valid = True
        state.online = 8
        state.in_game = 2
        state.rooms[:] = [1, 0, 3, 4, 2]
        guarded = GuardedViewText()
        guarded.before[:] = [0xA5] * len(guarded.before)
        guarded.after[:] = [0x5A] * len(guarded.after)
        library.format_view(ctypes.byref(state), ctypes.byref(guarded.text))
        text = guarded.text

        assert text.relay_title.decode() == "Relay: ON"
        assert text.channel_title.decode() == "Channel: 5 (ignored)"
        assert text.passphrase_title.decode() == "Room passphrase: 4321"
        assert text.overlay.decode() == "BBP:OK C:- P:4321"
        assert text.relay_status.decode() == "OK"
        assert text.latency.decode() == (
            "Connect: 123 ms\nRelay RTT: 41 ms  One-way: ~21 ms"
        )
        assert text.statistics.decode() == (
            "Recruiting: 10  In game: 2\nOnline: 8\n"
            "Ch1:1 Ch2:0 Ch3:3 Ch4:4 Ch5:2"
        )
        assert list(guarded.before) == [0xA5] * len(guarded.before)
        assert list(guarded.after) == [0x5A] * len(guarded.after)

        state.enabled = False
        state.connected = False
        state.channel = 0
        state.pin = 0
        state.latency_valid = False
        state.status_valid = False
        guarded = GuardedViewText()
        guarded.before[:] = [0xA5] * len(guarded.before)
        guarded.after[:] = [0x5A] * len(guarded.after)
        library.format_view(ctypes.byref(state), ctypes.byref(guarded.text))
        text = guarded.text
        assert text.relay_title.decode() == "Relay: OFF"
        assert text.channel_title.decode() == "Channel: 1"
        assert text.passphrase_title.decode() == "Room passphrase: 0000"
        assert text.overlay.decode() == ""
        assert text.relay_status.decode() == "OFF"
        assert text.latency.decode() == "Connect: --\nRelay RTT: --  One-way: --"
        assert text.statistics.decode() == (
            "Recruiting: --  In game: --\nOnline: --\n"
            "Ch1:-- Ch2:-- Ch3:-- Ch4:-- Ch5:--"
        )
        assert list(guarded.before) == [0xA5] * len(guarded.before)
        assert list(guarded.after) == [0x5A] * len(guarded.after)

        state = ViewState()
        state.enabled = True
        state.connecting = True
        state.channel = 255
        state.pin = 65535
        state.latency_valid = True
        state.connect_ms = 0xFFFFFFFF
        state.relay_rtt_ms = 0xFFFFFFFF
        state.status_valid = True
        state.online = 0xFFFF
        state.in_game = 0xFFFF
        state.rooms[:] = [0xFF] * 5
        guarded = GuardedViewText()
        guarded.before[:] = [0xA5] * len(guarded.before)
        guarded.after[:] = [0x5A] * len(guarded.after)
        library.format_view(ctypes.byref(state), ctypes.byref(guarded.text))
        text = guarded.text
        assert text.relay_title.decode() == "Relay: ON"
        assert text.channel_title.decode() == "Channel: 256 (ignored)"
        assert text.passphrase_title.decode() == "Room passphrase: 5535"
        assert text.overlay.decode() == "BBP:NG C:- P:5535"
        assert text.relay_status.decode() == "CONNECTING"
        assert text.latency.decode() == (
            "Connect: 4294967295 ms\nRelay RTT: 4294967295 ms  "
            "One-way: ~2147483648 ms"
        )
        assert text.statistics.decode() == (
            "Recruiting: 1275  In game: 65535\nOnline: 65535\n"
            "Ch1:255 Ch2:255 Ch3:255 Ch4:255 Ch5:255"
        )
        assert list(guarded.before) == [0xA5] * len(guarded.before)
        assert list(guarded.after) == [0x5A] * len(guarded.after)
        for field, capacity in (
            (text.relay_title, 16), (text.channel_title, 32),
            (text.passphrase_title, 32), (text.overlay, 32),
            (text.relay_status, 12), (text.latency, 96),
            (text.statistics, 128),
        ):
            assert len(field) < capacity, f"formatted field exceeds capacity {capacity}: {field!r}"
    assert not re.search(r"\bsnprintf\s*\(", read_c(MENU_SOURCE)), (
        "BBP menu source must not reintroduce the newlib snprintf dependency"
    )


def test_query_reason_identifies_partial_timeouts_without_masking_transport_errors():
    assert "BbpOnline_QueryReason" in VIEW_HEADER.read_text(encoding="utf-8"), (
        "timeout reasons do not distinguish partial query results yet"
    )
    with tempfile.TemporaryDirectory() as directory:
        library = _compile_with_luma_formatter(directory)
        library.query_reason.argtypes = [
            ctypes.c_char_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_bool,
        ]
        library.query_reason.restype = ctypes.c_char_p

        assert library.query_reason(b"No valid response within 5s", True, True, False) == (
            b"Status unavailable"
        )
        assert library.query_reason(b"No valid response within 5s", True, False, True) == (
            b"Probe unavailable"
        )
        assert library.query_reason(b"No valid response within 5s", True, False, False) == (
            b"No valid response within 5s"
        )
        assert library.query_reason(b"Network error", True, True, False) == b"Network error"
        assert library.query_reason(b"Server is busy", True, False, False) == b"Server is busy"


def test_endpoint_resolution_failure_does_not_guess_dns_vs_invalid_value():
    query = function_body(read_c(MENU_SOURCE), "bbpQuery")
    assert re.search(
        r'out->reason\s*=\s*"Endpoint unavailable"\s*;\s*'
        r'if\s*\(\s*!UdsRedirect_ResolveBbpEndpoint\s*\(\s*endpoint\s*,\s*'
        r'&address\s*,\s*&port\s*\)\s*\)\s*goto\s+cleanup\s*;',
        query,
        re.S,
    )


def test_query_reply_matcher_requires_type_marker_shape_and_current_nonce():
    with tempfile.TemporaryDirectory() as directory:
        library = _compile(directory, [MESSAGE_SOURCE])
        library.udsRelayV3HeaderEncode.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Header),
        ]
        library.udsRelayV3HeaderEncode.restype = ctypes.c_bool
        library.udsRelayV3QueryReplyMatches.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_void_p,
        ]
        library.udsRelayV3QueryReplyMatches.restype = ctypes.c_bool

        nonce = bytes.fromhex("0102030405060708")
        header = Header()
        header.packet_type = 0x14
        header.token[:] = b"BBP_PROXY_ACCESS"
        header.fragment_count = 1
        header.logical_body_length = 20
        encoded_header = ctypes.create_string_buffer(32)
        assert library.udsRelayV3HeaderEncode(
            encoded_header, len(encoded_header), ctypes.byref(header)
        )
        body = nonce + bytes.fromhex("080002000100030402000000")
        assert len(body) == 20
        packet = ctypes.create_string_buffer(encoded_header.raw + body)
        expected_nonce = ctypes.create_string_buffer(nonce)
        assert library.udsRelayV3QueryReplyMatches(
            packet, len(packet) - 1, 0x14, expected_nonce
        )
        assert not library.udsRelayV3QueryReplyMatches(
            packet, len(packet) - 1, 0x12, expected_nonce
        )
        stale_nonce = ctypes.create_string_buffer(bytes.fromhex("1112131415161718"))
        assert not library.udsRelayV3QueryReplyMatches(
            packet, len(packet) - 1, 0x14, stale_nonce
        )
        malformed_body = nonce + bytes.fromhex("080002000100030402000100")
        malformed = ctypes.create_string_buffer(encoded_header.raw + malformed_body)
        assert not library.udsRelayV3QueryReplyMatches(
            malformed, len(malformed) - 1, 0x14, expected_nonce
        )


if __name__ == "__main__":
    test_relay_overlay_keeps_menu_and_cursor_positions()
    test_view_formatter_preserves_counts_and_marks_unavailable_values()
    test_query_reason_identifies_partial_timeouts_without_masking_transport_errors()
    test_endpoint_resolution_failure_does_not_guess_dns_vs_invalid_value()
    test_query_reply_matcher_requires_type_marker_shape_and_current_nonce()
