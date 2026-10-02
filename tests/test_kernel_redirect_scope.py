import re

from _support import ROOT, function_body, read_c


def test_redirect_is_opt_in_and_limited_to_bbp_and_dlp():
    hook = read_c(ROOT / "k11_extension/source/svc/SendSyncRequest.c")
    info = read_c(ROOT / "k11_extension/source/svc/GetSystemInfo.c")

    target = function_body(hook, "BbpProxy_IsTargetProcess")
    pairs = {
        (int(high, 16), int(low, 16))
        for high, low in re.findall(
            r"titleIdHigh\s*==\s*(0x[0-9A-Fa-f]+)[uU]?\s*&&\s*"
            r"titleIdLow\s*==\s*(0x[0-9A-Fa-f]+)[uU]?",
            target,
        )
    }
    assert pairs == {(0x00040000, 0x000A0B00), (0x00040130, 0x00002802)}

    hook_body = function_body(hook, "SendSyncRequestHook")
    ndm_rewrite = re.search(
        r"case\s+0x10042\s*:\s*\{(.*?)\n\s*case\s+0x10082\s*:",
        hook_body,
        re.S,
    )
    assert ndm_rewrite is not None
    assert "g_bbpProxyRedirectEnabled != 0u" in ndm_rewrite.group(1)

    service_open = re.search(
        r"case\s+0x50100\s*:\s*\{(.*?)\n\s*case\s+0x80040\s*:",
        hook_body,
        re.S,
    )
    assert service_open is not None
    service_open = service_open.group(1)
    assert re.search(
        r'strcmp\s*\(\s*name\s*,\s*"nwm::UDS"\s*\)\s*==\s*0',
        service_open,
    )
    assert "g_bbpProxyRedirectEnabled" in service_open
    assert "BbpProxy_IsTargetProcess" in service_open
    assert '"plg:UDS"' in service_open

    info_body = function_body(info, "GetSystemInfoHook")
    assert re.search(r"volatile\s+u32\s+g_bbpProxyRedirectEnabled\s*=\s*0\s*;", info)
    assert re.search(r"case\s+0x310\s*:", info_body)
    assert re.search(r"case\s+0x311\s*:", info_body)
    assert re.search(
        r'memcmp\s*\(\s*codeSet->processName\s*,\s*"rosalina"\s*,\s*8\s*\)',
        info_body,
    )
    assert re.search(r"&\s*g_bbpProxyRedirectEnabled", info) is None


if __name__ == "__main__":
    test_redirect_is_opt_in_and_limited_to_bbp_and_dlp()
