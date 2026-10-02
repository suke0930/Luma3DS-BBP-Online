/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <3ds.h>
#include <arpa/inet.h>
#include <string.h>

#include "menus/bbp_online.h"
#include "menus/bbp_online_view.h"
#include "uds_redirect.h"
#include "bbp_relay_message.h"
#include "bbp_secure_transport.h"
#include "draw.h"
#include "fmt.h"
#include "minisoc.h"
#include "menu.h"
#include "sock_util.h"

static void showStatus(void);
static void toggleRelay(void);
static void showServers(void);
static void editChannel(void);
static void editPin(void);
static void showQuery(const char *endpointOverride, bool includeStatus);
static char relayTitle[16], channelTitle[32], pinTitle[32];

Menu bbpOnlineMenu = {
    "BBP Online",
    {
        { "Status", METHOD, .method = showStatus },
        { relayTitle, METHOD, .method = toggleRelay },
        { "Relay server...", METHOD, .method = showServers },
        { channelTitle, METHOD, .method = editChannel },
        { pinTitle, METHOD, .method = editPin },
        {},
    }
};

static void fillViewState(BbpOnlineViewState *view, const UdsBbpSnapshot *state,
                          bool latencyValid, u32 connectMs, u32 rttMs,
                          bool statusValid, u16 online, u16 inGame,
                          const u8 rooms[5])
{
    memset(view, 0, sizeof(*view));
    view->enabled = state->enabled;
    view->connected = state->connected;
    view->connecting = state->connecting;
    view->channel = state->channel;
    view->pin = state->pin;
    view->latency_valid = latencyValid;
    view->connect_ms = connectMs;
    view->relay_rtt_ms = rttMs;
    view->status_valid = statusValid;
    view->online = online;
    view->in_game = inGame;
    if (rooms != NULL)
        memcpy(view->rooms, rooms, sizeof(view->rooms));
}

void BbpOnline_UpdateMenu(char overlay[32])
{
    UdsBbpSnapshot state;
    BbpOnlineViewState view;
    BbpOnlineViewText text;
    UdsRedirect_GetBbpSnapshot(&state);
    fillViewState(&view, &state, false, 0, 0, false, 0, 0, NULL);
    BbpOnline_FormatView(&view, &text);
    strcpy(relayTitle, text.relay_title);
    strcpy(channelTitle, text.channel_title);
    strcpy(pinTitle, text.passphrase_title);
    strcpy(overlay, text.overlay);
}

static const char *configReason(u32 status)
{
    switch (status)
    {
    case UDS_PROXY_CONFIG_OK: return "";
    case UDS_PROXY_CONFIG_MARKER_IO: return "Cannot read enabled marker";
    case UDS_PROXY_CONFIG_RELAY_HOST: return "Invalid/unreadable endpoint";
    case UDS_PROXY_CONFIG_CLIENT_ID: return "Invalid/unreadable client.id";
    case UDS_PROXY_CONFIG_SAVE: return "SD save failed";
    case UDS_PROXY_CONFIG_REDIRECT: return "UDS redirect unavailable";
    case UDS_PROXY_CONFIG_SELECTION: return "Invalid selection: select a server";
    case UDS_PROXY_CONFIG_NAMESPACE: return "Server rejected Channel/PIN";
    default: return "Configuration error";
    }
}

static bool configResult(u32 result)
{
    if (result == BBP_CONFIG_OK) return true;
    const char *reason = result == BBP_CONFIG_BUSY ? "Close BBP before changing settings." :
                         result == BBP_CONFIG_INVALID ? "Invalid value or unavailable preset." :
                         result == BBP_CONFIG_PRESET_SAVED ? "Preset saved; selection save failed." :
                         "SD save failed; selection unchanged.";
    DispMessage("BBP Online", reason);
    return false;
}

static bool canEdit(void)
{
    return configResult(UdsRedirect_CanChangeBbpConfig() ? BBP_CONFIG_OK : BBP_CONFIG_BUSY);
}

static void drawStart(const char *title)
{
    Draw_Lock();
    Draw_ClearFramebuffer();
    Draw_DrawString(10, 10, COLOR_TITLE, title);
}

static void drawEnd(void)
{
    Draw_FlushFramebuffer();
    Draw_Unlock();
}

typedef struct {
    bool latencyValid, statusValid;
    u32 connectMs, rttMs;
    u16 online, inGame;
    u8 rooms[5];
    const char *reason;
} BbpQuery;

static UdsRelayV4Client s_queryV4;
static u8 s_queryWire[UDS_RELAY_V4_MAX_DATAGRAM] __attribute__((aligned(4)));
static u8 s_queryPlain[UDS_RELAY_V4_MAX_INNER] __attribute__((aligned(4)));

static u64 queryNowMs(void)
{
    return svcGetSystemTick() / ((u64)SYSCLOCK_ARM11 / 1000u);
}

static void bbpQuery(const char *endpoint, bool includeStatus, BbpQuery *out)
{
    memset(out, 0, sizeof(*out));
    u8 nonces[2][8], privateKey[32];
    out->reason = "Random source unavailable";
    if (!UdsRedirect_GenerateProbeNonce(nonces[0]) ||
        !UdsRedirect_GenerateProbeNonce(nonces[1]) ||
        !UdsRedirect_GenerateV4Key(privateKey))
        return;
    if (memcmp(nonces[0], nonces[1], sizeof(nonces[0])) == 0)
        nonces[1][0] ^= 1u;

    udsRelayV4ClientClear(&s_queryV4);
    if (!udsRelayV4ClientInit(&s_queryV4, privateKey))
    {
        memset(privateKey, 0, sizeof(privateKey));
        udsRelayV4ClientClear(&s_queryV4);
        return;
    }
    memset(privateKey, 0, sizeof(privateKey));

    out->reason = "Wi-Fi/SOC unavailable";
    if (!Wifi__IsConnected() || R_FAILED(miniSocInit()))
    {
        udsRelayV4ClientClear(&s_queryV4);
        return;
    }

    u32 address;
    u16 port;
    out->reason = "Endpoint unavailable";
    if (!UdsRedirect_ResolveBbpEndpoint(endpoint, &address, &port))
        goto cleanup;

    int fd = socSocket(AF_INET, SOCK_DGRAM, 0);
    out->reason = "Network error";
    if (fd >= 0)
    {
        struct sockaddr_in peer = {0};
        peer.sin_family = AF_INET;
        peer.sin_port = port;
        peer.sin_addr.s_addr = address;
        if (socConnect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0)
        {
            u64 start = queryNowMs();
            u64 nextHello = start + 500u;
            u64 probeStart = 0u;
            size_t wireLength = 0u;
            bool started = udsRelayV4ClientHello(
                &s_queryV4, s_queryWire, sizeof(s_queryWire), &wireLength) &&
                socSend(fd, s_queryWire, wireLength, 0) == (int)wireLength;
            bool queriesSent = false;
            bool probeSent = false;
            if (started) out->reason = "No valid response within 5s";
            while (started && !menuShouldExit && !preTerminationRequested &&
                   queryNowMs() - start < 5000u)
            {
                struct pollfd poll = {.fd = fd, .events = POLLIN};
                int ready = socPoll(&poll, 1, 0);
                if (ready < 0)
                {
                    out->reason = "Network error";
                    break;
                }
                if (ready > 0 && (poll.revents & POLLIN))
                {
                    int length = socRecv(fd, s_queryWire, sizeof(s_queryWire), MSG_DONTWAIT);
                    if (length > 0)
                    {
                        if (!udsRelayV4ClientReady(&s_queryV4))
                        {
                            size_t responseLength = 0u;
                            if (udsRelayV4ClientHandshake(
                                    &s_queryV4, s_queryWire, (size_t)length,
                                    s_queryPlain, sizeof(s_queryPlain),
                                    &responseLength))
                            {
                                u32 error = udsRelayV4ClientLastError(&s_queryV4);
                                if (error != 0u)
                                {
                                    out->reason = error == UDS_RELAY_V4_ERROR_SERVER_BUSY
                                        ? "Server is busy"
                                        : "Too many sessions from this IP";
                                    break;
                                }
                                if (responseLength != 0u &&
                                    socSend(fd, s_queryPlain, responseLength, 0) !=
                                        (int)responseLength)
                                {
                                    out->reason = "Network error";
                                    break;
                                }
                            }
                        }
                        else
                        {
                            size_t plainLength = 0u;
                            if (udsRelayV4ClientDecrypt(
                                    &s_queryV4, s_queryWire, (size_t)length,
                                    s_queryPlain, sizeof(s_queryPlain),
                                    &plainLength))
                            {
                                if (probeSent && !out->latencyValid &&
                                    udsRelayV3QueryReplyMatches(
                                        s_queryPlain, plainLength,
                                        UDS_RELAY_V3_PKT_PROBE_ACK, nonces[0]))
                                {
                                    u64 now = queryNowMs();
                                    out->connectMs = (u32)(now - start);
                                    out->rttMs = (u32)(now - probeStart);
                                    out->latencyValid = true;
                                }
                                if (includeStatus && !out->statusValid &&
                                    udsRelayV3QueryReplyMatches(
                                        s_queryPlain, plainLength,
                                        UDS_RELAY_V3_PKT_STATUS_REPLY, nonces[1]))
                                {
                                    out->online = s_queryPlain[40] |
                                        ((u16)s_queryPlain[41] << 8);
                                    out->inGame = s_queryPlain[42] |
                                        ((u16)s_queryPlain[43] << 8);
                                    memcpy(out->rooms, s_queryPlain + 44,
                                           sizeof(out->rooms));
                                    out->statusValid = true;
                                }
                            }
                        }
                    }
                }
                if (udsRelayV4ClientReady(&s_queryV4) && !queriesSent)
                {
                    UdsRelayV3Header header = {0};
                    header.fragment_count = 1;
                    memcpy(header.token, UDS_RELAY_V3_ADMISSION_MARKER, 16);
                    bool anySent = false;
                    for (u8 i = 0; i < (includeStatus ? 2u : 1u); ++i)
                    {
                        header.packet_type = i ? UDS_RELAY_V3_PKT_STATUS_QUERY :
                                                 UDS_RELAY_V3_PKT_PROBE;
                        header.logical_body_length = i ? 20u : 8u;
                        if (!udsRelayV3HeaderEncode(s_queryPlain,
                                                    sizeof(s_queryPlain), &header))
                            continue;
                        memset(s_queryPlain + UDS_RELAY_V3_HEADER_SIZE, 0, 20u);
                        memcpy(s_queryPlain + UDS_RELAY_V3_HEADER_SIZE,
                               nonces[i], sizeof(nonces[i]));
                        size_t innerLength = UDS_RELAY_V3_HEADER_SIZE +
                                             header.logical_body_length;
                        wireLength = 0u;
                        if (udsRelayV4ClientEncrypt(
                                &s_queryV4, s_queryPlain, innerLength,
                                s_queryWire, sizeof(s_queryWire), &wireLength) &&
                            socSend(fd, s_queryWire, wireLength, 0) ==
                                (int)wireLength)
                        {
                            anySent = true;
                            if (i == 0u)
                            {
                                probeStart = queryNowMs();
                                probeSent = true;
                            }
                        }
                    }
                    queriesSent = true;
                    if (!anySent)
                    {
                        out->reason = "Network error";
                        break;
                    }
                }
                if (!udsRelayV4ClientReady(&s_queryV4) &&
                    queryNowMs() >= nextHello)
                {
                    wireLength = 0u;
                    if (!udsRelayV4ClientHello(
                            &s_queryV4, s_queryWire, sizeof(s_queryWire), &wireLength) ||
                        socSend(fd, s_queryWire, wireLength, 0) != (int)wireLength)
                    {
                        out->reason = "Network error";
                        break;
                    }
                    nextHello = queryNowMs() + 500u;
                }
                if (out->latencyValid && (!includeStatus || out->statusValid))
                {
                    out->reason = "";
                    break;
                }
                svcSleepThread(10 * 1000 * 1000LL);
            }
        }
        socClose(fd);
    }
    out->reason = BbpOnline_QueryReason(out->reason, includeStatus,
                                         out->latencyValid, out->statusValid);

cleanup:
    miniSocExit();
    udsRelayV4ClientClear(&s_queryV4);
}

static void showQuery(const char *endpointOverride, bool includeStatus)
{
    bool retry = true;
    BbpQuery result;
    UdsBbpSnapshot state;
    char queryEndpoint[BBP_ENDPOINT_SIZE] = {0};
    while (!menuShouldExit)
    {
        UdsRedirect_GetBbpSnapshot(&state);
        if (retry)
        {
            drawStart("BBP Status");
            Draw_DrawString(10, 40, COLOR_WHITE, "Checking server (up to 5s)...");
            drawEnd();
            const char *endpoint = endpointOverride != NULL ? endpointOverride :
                state.valid[state.selected] ? state.endpoints[state.selected] : "";
            size_t endpointLength = strlen(endpoint);
            if (endpointLength >= sizeof(queryEndpoint))
                endpointLength = sizeof(queryEndpoint) - 1u;
            memcpy(queryEndpoint, endpoint, endpointLength);
            queryEndpoint[endpointLength] = '\0';
            bbpQuery(queryEndpoint, includeStatus, &result);
            retry = false;
            UdsRedirect_GetBbpSnapshot(&state);
        }
        BbpOnlineViewState view;
        BbpOnlineViewText text;
        fillViewState(&view, &state, result.latencyValid,
                      result.connectMs, result.rttMs, result.statusValid,
                      result.online, result.inGame, result.rooms);
        BbpOnline_FormatView(&view, &text);
        drawStart("BBP Status");
        Draw_DrawFormattedString(10, 32, COLOR_WHITE, "Relay: %s\nEndpoint: %s\n",
            text.relay_status, queryEndpoint[0] ? queryEndpoint : "Unavailable");
        Draw_DrawString(10, 58, COLOR_WHITE, text.latency);
        if (includeStatus)
            Draw_DrawString(10, 94, COLOR_WHITE, text.statistics);
        if (state.pin != 0u)
            Draw_DrawString(10, 138, COLOR_WHITE,
                            "Private (channel ignored)");
        Draw_DrawString(10, 159, COLOR_TITLE, configReason(state.configStatus));
        Draw_DrawString(10, 175, COLOR_TITLE, result.reason);
        Draw_DrawString(10, 203, COLOR_WHITE, "[X] retry   [B] back");
        drawEnd();
        u32 keys = waitInputWithTimeout(1000);
        if (keys & KEY_B) return;
        retry = (keys & KEY_X) != 0;
    }
}

static void showStatus(void)
{
    showQuery(NULL, true);
}

static void toggleRelay(void)
{
    bool enabled = UdsRedirect_IsProxyEnabled();
    if (!enabled && !canEdit()) return;
    if (!UdsRedirect_SetProxyEnabled(!enabled))
        DispMessage("BBP Online", configReason(UdsRedirect_GetProxyConfigStatus()));
}

static bool editDigits(const char *title, char *value)
{
    u32 cursor = 0;
    u32 length = (u32)strlen(value);
    while (!menuShouldExit)
    {
        drawStart(title);
        Draw_DrawString(10, 48, COLOR_WHITE, value);
        Draw_DrawCharacter(10 + cursor * SPACING_X, 60, COLOR_TITLE, '^');
        Draw_DrawString(10, 90, COLOR_WHITE,
                        "Left/Right: digit  Up/Down: value\n[A] save   [B] cancel");
        drawEnd();
        u32 keys = waitInput();
        if (keys & KEY_B) return false;
        if (keys & KEY_A) return true;
        if (keys & (KEY_LEFT | KEY_RIGHT))
        {
            do
            {
                cursor = (cursor + ((keys & KEY_LEFT) ? length - 1u : 1u)) % length;
            } while (value[cursor] < '0' || value[cursor] > '9');
        }
        if (keys & KEY_UP)
            value[cursor] = (char)('0' + (value[cursor] - '0' + 1) % 10);
        if (keys & KEY_DOWN)
            value[cursor] = (char)('0' + (value[cursor] - '0' + 9) % 10);
    }
    return false;
}

static void editChannel(void)
{
    if (!canEdit()) return;
    UdsBbpSnapshot state;
    UdsRedirect_GetBbpSnapshot(&state);
    u8 channel = state.channel;
    while (!menuShouldExit)
    {
        drawStart("BBP Channel");
        for (u8 i = 0; i < 5; ++i)
            Draw_DrawFormattedString(25, 36 + i * 22, COLOR_WHITE, "Channel %u", i + 1u);
        Draw_DrawCharacter(10, 36 + channel * 22, COLOR_TITLE, '>');
        if (state.pin != 0u)
            Draw_DrawString(10, 145, COLOR_WHITE, "Private: channel is ignored.");
        Draw_DrawString(10, 168, COLOR_WHITE, "Up/Down: move  [A] save  [B] cancel");
        drawEnd();
        u32 keys = waitInput();
        if (keys & KEY_B) return;
        if (keys & KEY_UP) channel = (u8)((channel + 4u) % 5u);
        if (keys & KEY_DOWN) channel = (u8)((channel + 1u) % 5u);
        if (keys & KEY_A)
        {
            (void)configResult(UdsRedirect_SetBbpMatchmaking(channel, state.pin));
            return;
        }
    }
}

static void editPin(void)
{
    if (!canEdit()) return;
    UdsBbpSnapshot state;
    UdsRedirect_GetBbpSnapshot(&state);
    char value[5];
    sprintf(value, "%04u", state.pin % 10000u);
    if (!editDigits("Room PIN: 0000 = public", value)) return;
    u16 pin = 0;
    for (u8 i = 0; i < 4; ++i)
        pin = (u16)(pin * 10u + (u16)(value[i] - '0'));
    (void)configResult(UdsRedirect_SetBbpMatchmaking(state.channel, pin));
}

static void showServers(void)
{
    UdsBbpSnapshot state;
    UdsRedirect_GetBbpSnapshot(&state);
    u8 slot = state.selected;
    while (!menuShouldExit)
    {
        UdsRedirect_GetBbpSnapshot(&state);
        drawStart("BBP Relay server");
        for (u8 i = 0; i < BBP_ENDPOINT_COUNT; ++i)
        {
            if (i == 0)
                Draw_DrawFormattedString(25, 36, COLOR_WHITE, "Official: %s%s",
                    state.valid[0] ? state.endpoints[0] : "Unavailable",
                    state.selected == 0 ? " *" : "");
            else
                Draw_DrawFormattedString(25, 36 + i * 22, COLOR_WHITE, "Custom %u: %s%s",
                    i, state.valid[i] ? state.endpoints[i] : "Invalid",
                    i == state.selected ? " *" : "");
        }
        Draw_DrawCharacter(10, 36 + slot * 22, COLOR_TITLE, '>');
        Draw_DrawString(10, 150, COLOR_WHITE, "[A] select/check   [X] edit\n[B] back");
        drawEnd();
        u32 keys = waitInput();
        if (keys & KEY_B) return;
        if (keys & KEY_UP) slot = (u8)((slot + BBP_ENDPOINT_COUNT - 1u) % BBP_ENDPOINT_COUNT);
        if (keys & KEY_DOWN) slot = (u8)((slot + 1u) % BBP_ENDPOINT_COUNT);
        if (!(keys & (KEY_A | KEY_X))) continue;
        if (slot == 0 && (keys & KEY_X)) continue;
        if (!canEdit()) continue;
        if (slot == 0)
        {
            if (configResult(UdsRedirect_SetBbpEndpoint(0, NULL)))
                showQuery(NULL, false);
            continue;
        }
        if (keys & KEY_X)
        {
            u8 address[4] = {192, 168, 0, 0};
            u16 port = 24873;
            if (state.valid[slot])
                (void)udsRelayV3HostParse(state.endpoints[slot],
                                          strlen(state.endpoints[slot]), address, &port);
            char value[BBP_ENDPOINT_SIZE];
            sprintf(value, "%03u.%03u.%03u.%03u:%05u",
                    address[0], address[1], address[2], address[3], port);
            while (editDigits("Custom IPv4:port", value))
            {
                if (configResult(UdsRedirect_SetBbpEndpoint(slot, value)))
                {
                    UdsRedirect_GetBbpSnapshot(&state);
                    showQuery(state.endpoints[slot], false);
                    break;
                }
            }
        }
        else if (configResult(UdsRedirect_SetBbpEndpoint(slot, NULL)))
        {
            showQuery(NULL, false);
        }
    }
}
