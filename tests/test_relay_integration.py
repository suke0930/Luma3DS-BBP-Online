import re

from _support import ROOT, call_match, function_body, read_c


SOURCE = ROOT / "sysmodules/rosalina/source/uds_redirect.c"
MAIN = ROOT / "sysmodules/rosalina/source/main.c"


def test_only_v4_wraps_v3_messages_on_the_network():
    source = read_c(SOURCE)
    assert re.search(r'#\s*include\s*"bbp_secure_transport\.h"', source)
    send = function_body(source, "relayV3SendMessage")
    encode = call_match(send, "udsRelayV3MessageEncode")
    ready = call_match(send, "udsRelayV4ClientReady")
    encrypt = call_match(send, "udsRelayV4ClientEncrypt")
    send_encrypted = re.search(
        r"\bsocSend\s*\(\s*s_relaySock\s*,\s*s_relayV4Tx\s*,", send
    )
    assert encode and ready and encrypt and send_encrypted
    assert ready.start() < encode.start() < encrypt.start() < send_encrypted.start()
    assert re.search(r"\bsocSend\s*\(\s*s_relaySock\s*,\s*s_relayV3Tx\s*,", send) is None


def test_v4_is_decrypted_before_v3_reassembly():
    source = read_c(SOURCE)
    loop = function_body(source, "relayV3ThreadMain")
    assert "UDS_RELAY_V4_MAX_DATAGRAM" in loop
    assert re.search(
        r"udsRelayV4ClientHandshake\s*\(\s*&s_relayV4Client", loop
    )
    decrypt = re.search(
        r"udsRelayV4ClientDecrypt\s*\(\s*&s_relayV4Client", loop
    )
    reassemble = re.search(
        r"udsRelayV3ReassemblerPush\s*\(\s*&s_relayV3Reassembler\s*,\s*"
        r"s_relayV4Plain\s*,",
        loop,
    )
    assert decrypt and reassemble and decrypt.start() < reassemble.start()


def test_relay_thread_starts_with_proxy_disabled():
    source = read_c(SOURCE)
    main = read_c(MAIN)
    assert re.search(r"static\s+volatile\s+bool\s+s_proxyEnabled\s*=\s*false\s*;", source)
    assert re.search(r"s_proxyEnabled\s*=\s*false\s*;", source)
    load = re.search(r"\bUdsRedirect_LoadConfig\s*\(", main)
    relay_thread = re.search(r"\bUdsRedirect_CreateRelayThread\s*\(", main)
    service_manager = re.search(r"\bServiceManager_Run\s*\(", main)
    assert load and relay_thread and service_manager
    assert load.start() < service_manager.start()
    assert relay_thread.start() < service_manager.start()


def test_hle_has_no_forwarding_or_debug_diagnostic_path():
    source = read_c(SOURCE)
    for excluded in (
        "s_forwardMode", "svcSendSyncRequest(s_realNwm)", "g_plgUdsStats",
        "UdsTrace_", "diagMark(", "fwdAdd(", "UDS_RELAY_V2_",
        "s_relayV3Close", "RELAY_V3_CLOSE_", "s_relayV3GateReason",
    ):
        assert excluded not in source


def test_minisoc_dns_resolver_serializes_and_validates_static_buffer_ipc():
    source = read_c(ROOT / "sysmodules/rosalina/source/minisoc.c")
    resolver = function_body(source, "miniSocResolveIPv4")
    assert re.search(
        r"static\s+u8\s+response\s*\[\s*0x1A88\s*\]\s*"
        r"__attribute__\s*\(\(\s*aligned\s*\(\s*4\s*\)\s*\)\)\s*;",
        resolver,
    )
    assert re.search(
        r"static\s+RecursiveLock\s+lock\s*=\s*__LOCK_INITIALIZER_RECURSIVE\s*;",
        resolver,
    )
    assert re.search(r"length\s*==\s*0\s*\|\|\s*length\s*>\s*253u?", resolver)
    lock = re.search(r"RecursiveLock_Lock\s*\(\s*&lock\s*\)", resolver)
    ipc = re.search(r"svcSendSyncRequest\s*\(\s*miniSocHandle\s*\)", resolver)
    unlock = re.search(r"RecursiveLock_Unlock\s*\(\s*&lock\s*\)", resolver)
    assert lock and ipc and unlock and lock.start() < ipc.start() < unlock.start()
    assert re.search(
        r"memset\s*\(\s*response\s*,\s*0\s*,\s*sizeof\s*\(\s*response\s*\)\s*\)",
        resolver,
    )
    assert re.search(r"resolved\s*==\s*0u?\s*\|\|\s*resolved\s*==\s*UINT32_MAX", resolver)


if __name__ == "__main__":
    test_only_v4_wraps_v3_messages_on_the_network()
    test_v4_is_decrypted_before_v3_reassembly()
    test_relay_thread_starts_with_proxy_disabled()
    test_hle_has_no_forwarding_or_debug_diagnostic_path()
    test_minisoc_dns_resolver_serializes_and_validates_static_buffer_ipc()
