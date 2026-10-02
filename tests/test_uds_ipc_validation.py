import subprocess
import tempfile
from pathlib import Path

from _support import ROOT, function_body, read_c


SOURCE = ROOT / "sysmodules/rosalina/source/uds_redirect.c"


HARNESS_PREFIX = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint32_t Handle;

#define IPC_MakeHeader(id, normal, translate) \
    (((u32)(id) << 16) | (((u32)(normal) & 0x3Fu) << 6) | ((u32)(translate) & 0x3Fu))
#define IPC_Desc_SharedHandles(count) (((u32)((count) - 1u)) << 26)
#define IPC_Desc_MoveHandles(count) ((((u32)((count) - 1u)) << 26) | 0x10u)
#define IPC_Desc_CurProcessId() 0x20u
#define IPC_Desc_StaticBuffer(size, id) (((u32)(size) << 14) | (((u32)(id) & 0xFu) << 10) | 2u)
#define IPC_Desc_PXIBuffer(size, id, readOnly) \
    (((u32)(size) << 8) | (((u32)(id) & 0xFu) << 4) | ((readOnly) ? 6u : 4u))
#define IPC_Desc_Buffer(size, rights) (((u32)(size) << 4) | 8u | (rights))
#define IPC_BUFFER_R 2u
#define IPC_BUFFER_W 4u
#define IPC_BUFFER_RW (IPC_BUFFER_R | IPC_BUFFER_W)
#define UDS_OUT_OF_RESOURCE 0xC8A10000u
#define UDS_PROXY_CONFIG_OK 0u
#define UDS_NODE_BROADCAST 0xFFFFu

typedef struct
{
    u32 cmdId;
    Handle sharedMemory;
    Handle scanEvent;
    u32 bufferDescriptor;
    u32 bufferPointer;
    bool hasSharedMemory;
    bool hasScanEvent;
    bool hasMappedBuffer;
} UdsIpcValidated;

static u8 s_sb0[0x1000];
static u8 s_sb5[0x1000];
static bool s_proxyEnabled;
static u32 s_proxyConfigStatus;
static u32 command_buffer[64];
static u32 hle_calls;
static u32 close_calls;
static Handle closed_handle;
static Handle closed_handles[64];
static u32 setup_calls;
static u32 last_hle_cmd;

static void svcCloseHandle(Handle handle)
{
    if (close_calls < sizeof(closed_handles) / sizeof(closed_handles[0]))
        closed_handles[close_calls] = handle;
    ++close_calls;
    closed_handle = handle;
}

static u32 *getThreadCommandBuffer(void) { return command_buffer; }
static void setupStaticBuffers(void) { ++setup_calls; }
static void hleHandle(u32 *cmdbuf, u32 cmdId)
{
    (void)cmdbuf;
    ++hle_calls;
    last_hle_cmd = cmdId;
}

"""


def _production_harness():
    source = read_c(SOURCE)
    handler = function_body(source, "UdsRedirect_HandleCommands")
    if "relayV3ValidateCommand(" not in handler:
        raise AssertionError(
            "UdsRedirect_HandleCommands must validate the IPC shape before dispatch"
        )

    names = (
        "relayV3SendToValuesValid",
        "relayV3TranslatedHandleCount",
        "relayV3ValidateCommand",
        "relayV3RejectMalformedCommand",
        "relayV3RejectCommand",
        "UdsRedirect_HandleCommands",
    )
    definitions = "\n".join(
        _function_definition(source, name) for name in names
    )
    return HARNESS_PREFIX + definitions + HARNESS_TESTS


def _function_definition(source, name):
    import re

    code = source
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^{};]*\)\s*\{", code, re.S)
    if match is None:
        raise AssertionError(f"production C function not found: {name}")
    start = code.rfind("\n", 0, match.start()) + 1
    opening = match.end() - 1
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[start : index + 1]
    raise AssertionError(f"unterminated production C function: {name}")


HARNESS_TESTS = r"""
static void reset_state(void)
{
    memset(command_buffer, 0, sizeof(command_buffer));
    hle_calls = 0;
    close_calls = 0;
    closed_handle = 0;
    memset(closed_handles, 0, sizeof(closed_handles));
    setup_calls = 0;
    last_hle_cmd = 0;
    s_proxyConfigStatus = UDS_PROXY_CONFIG_OK;
}

static void require(bool condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        __builtin_abort();
    }
}

static void make_valid(u32 *cmdbuf, u32 cmdId)
{
    memset(cmdbuf, 0, 64u * sizeof(u32));
    switch (cmdId)
    {
    case 0x03: case 0x08: case 0x0A:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 0, 0);
        break;
    case 0x05:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, 0);
        cmdbuf[1] = 0xFFFF;
        break;
    case 0x07:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 2, 0);
        cmdbuf[1] = 6;
        cmdbuf[2] = 1;
        break;
    case 0x1A:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 0, 0);
        break;
    case 0x0B:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 0, 0);
        break;
    case 0x0D:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, 0);
        cmdbuf[1] = 1;
        break;
    case 0x0F:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 16, 4);
        cmdbuf[1] = 64;
        cmdbuf[17] = IPC_Desc_SharedHandles(1);
        cmdbuf[18] = 101;
        cmdbuf[19] = IPC_Desc_Buffer(64, IPC_BUFFER_W);
        cmdbuf[20] = 0x2000;
        break;
    case 0x12:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 4, 0);
        break;
    case 0x13:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, 0);
        break;
    case 0x14:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 3, 0);
        cmdbuf[2] = 2;
        cmdbuf[3] = 5;
        break;
    case 0x17:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 6, 2);
        cmdbuf[4] = 2;
        cmdbuf[5] = 5;
        cmdbuf[7] = IPC_Desc_StaticBuffer(8, 5);
        cmdbuf[8] = 0x3000;
        break;
    case 0x1B:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 12, 2);
        cmdbuf[1] = 0x3000;
        cmdbuf[13] = IPC_Desc_SharedHandles(1);
        cmdbuf[14] = 202;
        break;
    case 0x1D:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, 4);
        cmdbuf[1] = 5;
        cmdbuf[2] = IPC_Desc_StaticBuffer(0x108, 1);
        cmdbuf[3] = 0x4000;
        cmdbuf[4] = IPC_Desc_StaticBuffer(5, 0);
        cmdbuf[5] = 0x5000;
        break;
    case 0x1E:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 2, 4);
        cmdbuf[1] = 1;
        cmdbuf[2] = 5;
        cmdbuf[3] = IPC_Desc_StaticBuffer(0x108, 1);
        cmdbuf[4] = 0x4000;
        cmdbuf[5] = IPC_Desc_StaticBuffer(5, 0);
        cmdbuf[6] = 0x5000;
        break;
    case 0x1F:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 0, 6);
        cmdbuf[1] = IPC_Desc_StaticBuffer(0x108, 1);
        cmdbuf[2] = 0x4000;
        cmdbuf[3] = IPC_Desc_StaticBuffer(0xFE, 2);
        cmdbuf[4] = 0x5000;
        cmdbuf[5] = IPC_Desc_StaticBuffer(0xFE, 3);
        cmdbuf[6] = 0x6000;
        break;
    case 0x21:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 2, 0);
        break;
    case 0x22:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 16, 2);
        cmdbuf[1] = 64;
        cmdbuf[17] = IPC_Desc_Buffer(64, IPC_BUFFER_W);
        cmdbuf[18] = 0x7000;
        break;
    default:
        __builtin_abort();
    }
}

static bool validate(u32 *cmdbuf, UdsIpcValidated *validated)
{
    return relayV3ValidateCommand(cmdbuf, cmdbuf[0] >> 16, validated);
}

static void reject_unknown_handles(u32 descriptor, u32 count,
                                   const Handle *handles)
{
    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 0, count + 1u);
    command_buffer[1] = descriptor;
    for (u32 i = 0; i < count; ++i)
        command_buffer[2u + i] = handles[i];
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0, "unknown translated handles reached HLE");
    require(close_calls == count, "unknown translated handles were not reclaimed");
    for (u32 i = 0; i < count; ++i)
        require(closed_handles[i] == handles[i],
                "cleanup closed a value other than a translated handle");
    require(command_buffer[0] == IPC_MakeHeader(0, 1, 0) &&
                command_buffer[1] == 0xD9001830u,
            "unknown translated handles did not receive IPC validation error");
}

int main(void)
{
    static const u32 known[] = {
        0x03, 0x05, 0x07, 0x08, 0x0A, 0x0B, 0x0D, 0x0F, 0x12, 0x13,
        0x14, 0x17, 0x1A, 0x1B, 0x1D, 0x1E, 0x1F, 0x21, 0x22,
    };
    UdsIpcValidated validated;
    require(relayV3SendToValuesValid(0xFFFFu, 1u),
            "broadcast destination with nonzero channel rejected");
    require(relayV3SendToValuesValid(16u, 255u),
            "last node and maximum channel rejected");
    require(!relayV3SendToValuesValid(0u, 1u) &&
                !relayV3SendToValuesValid(17u, 1u) &&
                !relayV3SendToValuesValid(0xFFFEu, 1u),
            "invalid destination accepted");
    require(!relayV3SendToValuesValid(1u, 0u),
            "zero channel accepted");
    for (u32 i = 0; i < sizeof(known) / sizeof(known[0]); ++i)
    {
        make_valid(command_buffer, known[i]);
        require(validate(command_buffer, &validated), "known live IPC shape rejected");
        require(validated.cmdId == known[i], "validated command ID changed");
    }

    {
        static const u32 lifecycle[] = { 0x05, 0x07, 0x1A };
        for (u32 i = 0; i < sizeof(lifecycle) / sizeof(lifecycle[0]); ++i)
        {
            reset_state();
            make_valid(command_buffer, lifecycle[i]);
            s_proxyEnabled = true;
            UdsRedirect_HandleCommands(NULL);
            require(hle_calls == 1 && last_hle_cmd == lifecycle[i],
                    "known lifecycle command did not reach HLE");
            for (u32 enabled = 0; enabled <= 1; ++enabled)
            {
                for (u32 translate = 0; translate <= 1; ++translate)
                {
                    reset_state();
                    make_valid(command_buffer, lifecycle[i]);
                    command_buffer[0] += translate ? 2u : 0x40u;
                    s_proxyEnabled = enabled != 0;
                    UdsRedirect_HandleCommands(NULL);
                    require(hle_calls == 0 && command_buffer[1] == 0xD9001830u,
                            "malformed lifecycle command reached HLE");
                }
            }
        }
    }

    make_valid(command_buffer, 0x0F);
    command_buffer[0] = IPC_MakeHeader(0x0F, 15, 4);
    command_buffer[18] = 0xBADu;
    command_buffer[20] = 0x41414141u;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0, "bad 0x0F header reached HLE");
    require(close_calls == 0, "bad 0x0F header closed an untrusted handle");
    require(command_buffer[0] == IPC_MakeHeader(0, 1, 0) &&
                command_buffer[1] == 0xD9001830u,
            "bad 0x0F header did not return IPC validation error");

    reset_state();
    make_valid(command_buffer, 0x1B);
    command_buffer[0] = IPC_MakeHeader(0x1B, 11, 2);
    command_buffer[14] = 0xBEEFu;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0, "bad 0x1B header reached HLE");
    require(close_calls == 0, "bad 0x1B header closed an untrusted handle");
    require(command_buffer[0] == IPC_MakeHeader(0, 1, 0) &&
                command_buffer[1] == 0xD9001830u,
            "bad 0x1B header did not return IPC validation error");

    reset_state();
    make_valid(command_buffer, 0x0F);
    command_buffer[19] = IPC_Desc_Buffer(64, IPC_BUFFER_R);
    s_proxyEnabled = false;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0, "bad 0x0F permission reached HLE while proxy was off");
    require(close_calls == 1 && closed_handle == 101,
            "recognized translated scan event was not released");
    require(command_buffer[0] == IPC_MakeHeader(0x0F, 1, 2) &&
                command_buffer[1] == 0xD9001830u &&
                command_buffer[2] == IPC_Desc_Buffer(64, IPC_BUFFER_R) &&
                command_buffer[3] == 0x2000,
            "mapped buffer was not echoed on malformed 0x0F");

    reset_state();
    make_valid(command_buffer, 0x1B);
    command_buffer[0] = IPC_MakeHeader(0x1B, 12, 3);
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 1 && closed_handle == 202,
            "translated 0x1B handle was not reclaimed after bad translate count");

    reset_state();
    make_valid(command_buffer, 0x14);
    command_buffer[0] = IPC_MakeHeader(0x14, 2, 0);
    s_proxyEnabled = false;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 0 &&
                command_buffer[0] == IPC_MakeHeader(0, 1, 0) &&
                command_buffer[1] == 0xD9001830u,
            "bad normal count caused side effects while proxy was off");

    reset_state();
    make_valid(command_buffer, 0x17);
    command_buffer[7] = IPC_Desc_StaticBuffer(8, 4);
    require(!validate(command_buffer, &validated), "wrong static-buffer ID accepted");
    command_buffer[7] = IPC_Desc_StaticBuffer(4, 5);
    require(!validate(command_buffer, &validated), "wrong static-buffer length accepted");

    reset_state();
    make_valid(command_buffer, 0x1D);
    command_buffer[2] = IPC_Desc_StaticBuffer(0x108, 0);
    require(!validate(command_buffer, &validated), "wrong network buffer ID accepted");

    reset_state();
    make_valid(command_buffer, 0x22);
    command_buffer[17] = IPC_Desc_Buffer(64, IPC_BUFFER_RW);
    require(!validate(command_buffer, &validated), "wrong mapped-buffer permission accepted");
    command_buffer[17] = IPC_Desc_Buffer(65, IPC_BUFFER_W);
    require(!validate(command_buffer, &validated), "wrong mapped-buffer length accepted");

    reset_state();
    make_valid(command_buffer, 0x22);
    command_buffer[17] = IPC_Desc_Buffer(64, IPC_BUFFER_RW);
    s_proxyEnabled = false;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 0 &&
                command_buffer[0] == IPC_MakeHeader(0x22, 1, 2) &&
                command_buffer[1] == 0xD9001830u &&
                command_buffer[2] == IPC_Desc_Buffer(64, IPC_BUFFER_RW) &&
                command_buffer[3] == 0x7000,
            "malformed 0x22 did not safely echo its translated buffer while proxy was off");

    reset_state();
    make_valid(command_buffer, 0x21);
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 1 && last_hle_cmd == 0x21,
            "explicitly supported SetProbeResponseParam did not reach HLE");

    reset_state();
    memset(command_buffer, 0, sizeof(command_buffer));
    command_buffer[0] = IPC_MakeHeader(0x37, 0, 0);
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && command_buffer[0] == IPC_MakeHeader(0, 1, 0) &&
                command_buffer[1] == 0xD9001830u,
            "unknown command was not rejected");

    {
        const Handle one[] = { 301 };
        const Handle two[] = { 302, 303 };
        reject_unknown_handles(IPC_Desc_SharedHandles(1), 1, one);
        reject_unknown_handles(IPC_Desc_SharedHandles(2), 2, two);
        reject_unknown_handles(IPC_Desc_MoveHandles(1), 1, one);
        reject_unknown_handles(IPC_Desc_MoveHandles(2), 2, two);
    }

    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 2, 11);
    command_buffer[1] = IPC_Desc_SharedHandles(1);
    command_buffer[2] = 444;
    command_buffer[3] = IPC_Desc_StaticBuffer(0x20, 5);
    command_buffer[4] = 0x1000;
    command_buffer[5] = IPC_Desc_CurProcessId();
    command_buffer[6] = 0x12345678;
    command_buffer[7] = IPC_Desc_PXIBuffer(0x40, 2, false);
    command_buffer[8] = 0x2000;
    command_buffer[9] = IPC_Desc_Buffer(0x40, IPC_BUFFER_W);
    command_buffer[10] = 0x04001000;
    command_buffer[11] = IPC_Desc_MoveHandles(2);
    command_buffer[12] = 501;
    command_buffer[13] = 502;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 2 &&
                closed_handles[0] == 501 && closed_handles[1] == 502,
            "mixed translation walk confused non-handle words with handles");
    require(command_buffer[0] == IPC_MakeHeader(0x37, 1, 2) &&
                command_buffer[1] == 0xD9001830u &&
                command_buffer[2] == IPC_Desc_Buffer(0x40, IPC_BUFFER_W) &&
                command_buffer[3] == 0x04001000,
            "unknown command did not echo its kernel-translated mapped buffer");

    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 16, 4);
    for (u32 i = 1; i <= 16; ++i)
        command_buffer[i] = 0x500u + i;
    command_buffer[2] = 601;
    command_buffer[17] = IPC_Desc_SharedHandles(1);
    command_buffer[18] = 602;
    command_buffer[19] = IPC_Desc_Buffer(64, IPC_BUFFER_W);
    command_buffer[20] = 0x7000;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 1 && closed_handles[0] == 602,
            "unknown 0x0F-shaped command used normal words as translated handles");
    require(command_buffer[0] == IPC_MakeHeader(0x37, 1, 2) &&
                command_buffer[2] == IPC_Desc_Buffer(64, IPC_BUFFER_W) &&
                command_buffer[3] == 0x7000,
            "unknown 0x0F-shaped command did not preserve mapped-buffer cleanup");

    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 0, 5);
    command_buffer[1] = IPC_Desc_SharedHandles(1);
    command_buffer[2] = 701;
    command_buffer[3] = 0x30u;
    command_buffer[4] = IPC_Desc_SharedHandles(1);
    command_buffer[5] = 702;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(close_calls == 1 && closed_handles[0] == 701,
            "unknown translation type authorized closing a later raw handle");

    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 0, 2);
    command_buffer[1] = IPC_Desc_SharedHandles(2);
    command_buffer[2] = 801;
    command_buffer[3] = 802;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(close_calls == 0,
            "descriptor count beyond the translated span closed unproven handles");

    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 62, 2);
    command_buffer[63] = IPC_Desc_SharedHandles(1);
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(close_calls == 0,
            "translation span beyond the command buffer was consumed");

    reset_state();
    command_buffer[0] = IPC_MakeHeader(0x37, 62, 1);
    command_buffer[63] = IPC_Desc_StaticBuffer(0x20, 5);
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(close_calls == 0,
            "truncated static-buffer descriptor read beyond the command buffer");

    reset_state();
    make_valid(command_buffer, 0x1B);
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 1 && last_hle_cmd == 0x1B && close_calls == 0,
            "valid Initialize shape did not reach HLE with handle ownership intact");

    reset_state();
    make_valid(command_buffer, 0x0F);
    s_proxyEnabled = false;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 1 && closed_handle == 101 &&
                command_buffer[0] == IPC_MakeHeader(0x0F, 1, 2) &&
                command_buffer[2] == IPC_Desc_Buffer(64, IPC_BUFFER_W),
            "proxy-off valid scan did not clean up translated inputs");

    reset_state();
    make_valid(command_buffer, 0x0F);
    command_buffer[0] = IPC_MakeHeader(0x0F, 16, 5);
    command_buffer[17] = IPC_Desc_SharedHandles(2);
    command_buffer[18] = 303;
    command_buffer[19] = 304;
    command_buffer[20] = IPC_Desc_Buffer(64, IPC_BUFFER_W);
    command_buffer[21] = 0x2000;
    s_proxyEnabled = true;
    UdsRedirect_HandleCommands(NULL);
    require(hle_calls == 0 && close_calls == 2 && closed_handle == 304 &&
                command_buffer[0] == IPC_MakeHeader(0x0F, 1, 2) &&
                command_buffer[2] == IPC_Desc_Buffer(64, IPC_BUFFER_W) &&
                command_buffer[3] == 0x2000,
            "malformed scan did not release translated handles and mapping");

    puts("UDS IPC production validator cases passed");
    return 0;
}
"""


def test_uds_ipc_validation_and_dispatch_boundaries():
    harness = _production_harness()
    with tempfile.TemporaryDirectory(prefix="bbp-uds-ipc-") as temp_dir:
        source = Path(temp_dir) / "uds_ipc_validation.c"
        executable = Path(temp_dir) / "uds_ipc_validation"
        source.write_text(harness, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [str(executable)], check=True, capture_output=True, text=True
        )
        assert "UDS IPC production validator cases passed" in result.stdout


def test_sendto_route_guard_precedes_queue_publication():
    source = read_c(SOURCE)
    handler = function_body(source, "hleHandle")
    send_to = handler.index("case 0x17:")
    next_case = handler.index("case 0x14:", send_to)
    send_to_case = handler[send_to:next_case]
    guard = send_to_case.index(
        "if (relayV3SendToValuesValid(dst, channel))"
    )
    guard_open = send_to_case.index("{", guard)
    depth = 0
    guard_end = None
    for index in range(guard_open, len(send_to_case)):
        if send_to_case[index] == "{":
            depth += 1
        elif send_to_case[index] == "}":
            depth -= 1
            if depth == 0:
                guard_end = index
                break
    assert guard_end is not None
    publish = send_to_case.index("s_sendWrite = w + 1")
    reply = send_to_case.index("cmdbuf[0] = IPC_MakeHeader(0x17, 1, 0);")
    assert guard_open < publish < guard_end < reply


def test_known_lifecycle_replies_and_wifi_channel_snapshot():
    handler = function_body(read_c(SOURCE), "hleHandle")
    assert "case 0x1A:" in handler, "GetChannel needs an explicit output reply"
    cases = handler[handler.index("case 0x05:") : handler.index("case 0x08:")]
    prefix = HARNESS_PREFIX
    stub = _function_definition(prefix, "hleHandle")
    state = r"""
#define UDS_STATUS_DISCONNECTED 3u
#define UDS_STATUS_HOST 6u
#define UDS_STATUS_CLIENT 9u
#define UDS_STATUS_SPECTATOR 10u
#define RELAY_V3_ROLE_HOST 1u
static u32 s_connStatus;
static int s_connLock;
static int lock_depth;
static struct { u8 kind; u8 host_raw_network_info[0x108]; } s_relayV3Role;
static struct { bool valid; u8 network_info[0x108]; } s_relayV3SelectedRoom;
static void RecursiveLock_Lock(int *lock) { (void)lock; ++lock_depth; }
static void RecursiveLock_Unlock(int *lock) { (void)lock; --lock_depth; }
"""
    definition = "static void hleHandle(u32 *cmdbuf, u32 cmdId) { switch (cmdId) {\n"
    definition += cases + "default: __builtin_abort(); } }\n"
    prefix = prefix.replace(stub, state + definition)
    tests = r"""
static void check_channel(u32 expected)
{
    memset(command_buffer, 0xA5, sizeof(command_buffer));
    hleHandle(command_buffer, 0x1A);
    if (command_buffer[0] != IPC_MakeHeader(0x1A, 2, 0) ||
        command_buffer[1] != 0 || command_buffer[2] != expected || lock_depth != 0)
        __builtin_abort();
}
int main(void)
{
    for (u32 cmd = 5; cmd <= 7; cmd += 2)
    {
        hleHandle(command_buffer, cmd);
        if (command_buffer[0] != IPC_MakeHeader(cmd, 1, 0) || command_buffer[1] != 0)
            __builtin_abort();
    }
    s_connStatus = UDS_STATUS_DISCONNECTED;
    check_channel(0);
    s_connStatus = UDS_STATUS_HOST;
    s_relayV3Role.kind = RELAY_V3_ROLE_HOST;
    check_channel(11);
    s_relayV3Role.host_raw_network_info[6] = 6;
    check_channel(6);
    s_relayV3Role.kind = 2;
    s_relayV3SelectedRoom.valid = true;
    s_relayV3SelectedRoom.network_info[6] = 3;
    s_connStatus = UDS_STATUS_CLIENT;
    check_channel(3);
    s_connStatus = UDS_STATUS_SPECTATOR;
    check_channel(3);
    s_relayV3SelectedRoom.network_info[6] = 0;
    check_channel(11);
    s_connStatus = UDS_STATUS_DISCONNECTED;
    check_channel(0);
    puts("UDS known lifecycle replies passed");
    return 0;
}
"""
    with tempfile.TemporaryDirectory(prefix="bbp-uds-lifecycle-") as temp_dir:
        source = Path(temp_dir) / "uds_lifecycle.c"
        executable = Path(temp_dir) / "uds_lifecycle"
        source.write_text(prefix + tests, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function",
             "-Wno-unused-variable", "-Werror", str(source), "-o", str(executable)],
            check=True, capture_output=True, text=True,
        )
        result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
        assert "UDS known lifecycle replies passed" in result.stdout
