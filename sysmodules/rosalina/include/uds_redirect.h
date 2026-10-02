/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <3ds/types.h>

#define BBP_ENDPOINT_COUNT 4u
#define BBP_ENDPOINT_SIZE 22u

#define BBP_OFFICIAL_HOST "bbprelay.f5.si"
#define BBP_OFFICIAL_PORT 24873u
#define BBP_OFFICIAL_ENDPOINT "bbprelay.f5.si:24873"

typedef struct {
    char endpoints[BBP_ENDPOINT_COUNT][BBP_ENDPOINT_SIZE];
    bool valid[BBP_ENDPOINT_COUNT];
    u8 selected;
    u8 channel;
    u16 pin;
    bool enabled;
    bool connected;
    bool connecting;
    u32 configStatus;
    u32 generation;
} UdsBbpSnapshot;

enum {
    UDS_PROXY_CONFIG_OK = 0,
    UDS_PROXY_CONFIG_MARKER_IO,
    UDS_PROXY_CONFIG_RELAY_HOST,
    UDS_PROXY_CONFIG_CLIENT_ID,
    UDS_PROXY_CONFIG_SAVE,
    UDS_PROXY_CONFIG_REDIRECT,
    UDS_PROXY_CONFIG_SELECTION,
    UDS_PROXY_CONFIG_NAMESPACE,
};

enum {
    BBP_CONFIG_OK = 0,
    BBP_CONFIG_BUSY,
    BBP_CONFIG_INVALID,
    BBP_CONFIG_SAVE_FAILED,
    BBP_CONFIG_PRESET_SAVED,
};

bool UdsRedirect_CanChangeBbpConfig(void);
void UdsRedirect_GetBbpSnapshot(UdsBbpSnapshot *out);
u32 UdsRedirect_SetBbpMatchmaking(u8 channel, u16 pin);
u32 UdsRedirect_SetBbpEndpoint(u8 slot, const char *value);
bool UdsRedirect_GenerateProbeNonce(u8 nonce[8]);
bool UdsRedirect_GenerateV4Key(u8 key[32]);
bool UdsRedirect_ResolveBbpEndpoint(const char *endpoint, u32 *address, u16 *port);

void UdsRedirect_LoadConfig(void);
bool UdsRedirect_SetProxyEnabled(bool enabled);
bool UdsRedirect_IsProxyEnabled(void);
u32 UdsRedirect_GetProxyConfigStatus(void);

void UdsRedirect_HandleCommands(void *ctx);
void UdsRedirect_CreateRelayThread(void);
