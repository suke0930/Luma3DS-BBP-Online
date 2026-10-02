/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "fmt.h"

typedef struct {
    bool enabled;
    bool connected;
    bool connecting;
    uint8_t channel;
    uint16_t pin;
    bool latency_valid;
    uint32_t connect_ms;
    uint32_t relay_rtt_ms;
    bool status_valid;
    uint16_t online;
    uint16_t in_game;
    uint8_t rooms[5];
} BbpOnlineViewState;

typedef struct {
    char relay_title[16];
    char channel_title[32];
    char passphrase_title[32];
    char overlay[32];
    char relay_status[12];
    char latency[96];
    char statistics[128];
} BbpOnlineViewText;

static inline const char *BbpOnline_QueryReason(const char *reason,
                                                bool includeStatus,
                                                bool latencyValid,
                                                bool statusValid)
{
    if (strcmp(reason, "No valid response within 5s") != 0 || !includeStatus)
        return reason;
    if (latencyValid && !statusValid) return "Status unavailable";
    if (!latencyValid && statusValid) return "Probe unavailable";
    return reason;
}

static inline void BbpOnline_FormatView(const BbpOnlineViewState *state,
                                        BbpOnlineViewText *text)
{
    unsigned channel = (unsigned)state->channel + 1u;
    unsigned pin = (unsigned)state->pin % 10000u;
    const char *connection = !state->enabled ? "OFF" :
                             state->connected ? "OK" :
                             state->connecting ? "CONNECTING" : "NG";

    (void)sprintf(text->relay_title, "Relay: %s", state->enabled ? "ON" : "OFF");
    (void)sprintf(text->channel_title, "Channel: %u%s", channel,
                  pin != 0u ? " (ignored)" : "");
    (void)sprintf(text->passphrase_title, "Room passphrase: %04u", pin);

    if (!state->enabled)
        text->overlay[0] = '\0';
    else if (pin != 0u)
        (void)sprintf(text->overlay, "BBP:%s C:- P:%04u",
                      state->connected ? "OK" : "NG", pin);
    else
        (void)sprintf(text->overlay, "BBP:%s C:%u P:0000",
                      state->connected ? "OK" : "NG", channel);

    (void)sprintf(text->relay_status, "%s", connection);
    if (state->latency_valid)
    {
        unsigned oneWay = (unsigned)(state->relay_rtt_ms / 2u) +
                          (unsigned)(state->relay_rtt_ms & 1u);
        (void)sprintf(text->latency,
                      "Connect: %lu ms\nRelay RTT: %lu ms  One-way: ~%u ms",
                      (unsigned long)state->connect_ms,
                      (unsigned long)state->relay_rtt_ms, oneWay);
    }
    else
    {
        (void)sprintf(text->latency, "Connect: --\nRelay RTT: --  One-way: --");
    }

    if (state->status_valid)
    {
        unsigned recruiting = 0u;
        for (unsigned i = 0; i < 5u; ++i)
            recruiting += state->rooms[i];
        (void)sprintf(text->statistics,
                      "Recruiting: %u  In game: %u\nOnline: %u\n"
                      "Ch1:%u Ch2:%u Ch3:%u Ch4:%u Ch5:%u",
                      recruiting, (unsigned)state->in_game,
                      (unsigned)state->online, (unsigned)state->rooms[0],
                      (unsigned)state->rooms[1], (unsigned)state->rooms[2],
                      (unsigned)state->rooms[3], (unsigned)state->rooms[4]);
    }
    else
    {
        (void)sprintf(text->statistics,
                      "Recruiting: --  In game: --\nOnline: --\n"
                      "Ch1:-- Ch2:-- Ch3:-- Ch4:-- Ch5:--");
    }
}
