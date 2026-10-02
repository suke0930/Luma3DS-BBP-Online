/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <3ds.h>
#include <3ds/services/ps.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "uds_redirect.h"
#include "ifile.h"
#include "MyThread.h"
#include "menu.h"
#include "csvc.h"
#include "minisoc.h"
#include "sock_util.h"
#include "uds_beacon_scan.h"
#include "uds_send_fence.h"
#include "uds_dlp_advert.h"
#include "uds_recv_ring.h"
#include "bbp_relay_message.h"
#include "bbp_relay_rooms.h"
#include "bbp_secure_transport.h"
#include "pmdbgext.h"

/* Connection state is shared by the service and relay threads under s_connLock. */
#define UDS_STATUS_DISCONNECTED 3u
#define UDS_STATUS_HOST         6u
#define UDS_STATUS_CONNECTING   7u
#define UDS_STATUS_CLIENT       9u
#define UDS_STATUS_SPECTATOR    10u
#define UDS_REASON_NONE         0u
#define UDS_REASON_ESTABLISHED  1u
#define RELAY_NATIVE_SESSION_ID 1u
#define UDS_NODE_BROADCAST     0xFFFFu
#define RELAY_UDS_PAYLOAD_MAX  (UDS_RELAY_V3_MAX_LOGICAL_BODY - 32u)

static RecursiveLock s_connLock;
static bool s_connLockReady = false;
static RecursiveLock s_psLock;
static bool s_psLockReady = false;
static Handle s_connEvent = 0;
static bool s_connected = false;
static bool s_hosting = false;
static bool s_isSpectator = false;
static u8 s_maxNodes = 1;
static u16 s_ourNodeID = 0;
static u16 s_connChanged = 0;
static u16 s_connNodeMask = 0;
static u32 s_sessionId = 0;
static u32 s_connStatus = UDS_STATUS_DISCONNECTED;
static u32 s_connReason = UDS_REASON_NONE;
static bool s_wantJoin = false;
static bool s_joinInFlight = false;
static u32 s_joinAttemptSerial = 1;

static void connLockInitOnce(void)
{
    if (!s_connLockReady)
    {
        RecursiveLock_Init(&s_connLock);
        s_connLockReady = true;
    }
}

/* Serialize the ref-counted PS init/request/exit sequence. */
static void psLockInitOnce(void)
{
    if (!s_psLockReady)
    {
        RecursiveLock_Init(&s_psLock);
        s_psLockReady = true;
    }
}

static void connResetVisibleLocked(void)
{
    s_connStatus = UDS_STATUS_DISCONNECTED;
    s_connReason = UDS_REASON_NONE;
    s_connNodeMask = 0;
    s_connChanged = 0;
    s_ourNodeID = 0;
    s_sessionId = 0;
    s_hosting = false;
}

static MyThread s_relayThread;
static u8 CTR_ALIGN(8) s_relayThreadStack[0x4000];
static u8 s_relayRx[UDS_RELAY_V4_MAX_DATAGRAM] __attribute__((aligned(4)));
static int s_relaySock = -1;
static bool s_relayUp = false;

#define RELAY_V3_PATH_HOST "/luma/bbpproxy/relay.host"
#define RELAY_V3_PATH_CLIENT_ID "/luma/bbpproxy/client.id"
#define BBP_PATH_SELECTED "/luma/bbpproxy/relay.selected"
static const char *const s_bbpPresetPaths[BBP_ENDPOINT_COUNT] = {
    NULL, RELAY_V3_PATH_HOST, "/luma/bbpproxy/relay2.host",
    "/luma/bbpproxy/relay3.host"
};
static UdsBbpSnapshot s_bbpConfig;
static bool s_bbpSelectionValid = false;
static u32 s_bbpHealthGeneration;
static bool s_bbpConfirmed, s_bbpSocketOpen;
static u64 s_bbpLastRxMs, s_bbpStartedMs;
static u8 s_relayV3Channel;
static u16 s_relayV3Pin;
static u32 s_relayV3ConfigGeneration;

static u8 s_relayV3ClientId[16];
static u8 s_relayV3Nonce[16];
static u8 s_relayV3Token[16];
static u8 s_relayV3Scope[16];
static bool s_relayV3Confirmed = false;
static u32 s_relayV3RosterVersion = 0;
static u32 s_relayV3RetryAttempt = 0;
static u64 s_relayV3StartedMs = 0;
static u64 s_relayV3NextSendMs = 0;
static u64 s_relayV3LastRxMs = 0;
static u32 s_relayV3FragmentId = 1;
static UdsRelayV3Reassembler s_relayV3Reassembler;

static UdsRelayV3Message s_relayV3Message;
static UdsRelayV3Rooms s_relayV3Rooms;
static UdsRelayV3Room s_relayV3SelectedRoom;
static u8 s_relayV3SelectedRole = 0;
static u64 s_relayV3RoomListLastValidMs = 0;
static volatile bool s_proxyEnabled = false;
static volatile u32 s_proxyConfigStatus = UDS_PROXY_CONFIG_OK;
static volatile u32 s_proxyConfigGeneration = 1u;
static u8 s_relayV3Tx[2][UDS_RELAY_V3_MAX_DATAGRAM] __attribute__((aligned(4)));
static u16 s_relayV3TxLengths[2];
static UdsRelayV4Client s_relayV4Client;
static u8 s_relayV4Tx[UDS_RELAY_V4_MAX_DATAGRAM] __attribute__((aligned(4)));
static u8 s_relayV4Plain[UDS_RELAY_V4_MAX_INNER] __attribute__((aligned(4)));
static u8 s_relayV3DataBody[UDS_RELAY_V3_MAX_LOGICAL_BODY]
    __attribute__((aligned(4)));

#define RELAY_V3_HEARTBEAT_MS 5000u

#define RELAY_V3_ROLE_NONE 0u
#define RELAY_V3_ROLE_HOST 1u
#define RELAY_V3_ROLE_GUEST 2u

typedef struct {
    u64 epoch;
    u64 started_ms;
    u64 next_send_ms;
    u32 retry_attempt;
    u8 kind;
    u8 max_nodes;
    u8 acquire_type;
    u8 retire_type;
    u8 retire_reason;
    bool pending;
    bool active;
    bool retire_pending;
    bool host_descriptor_prepared;
    bool id_conflict_retried;
    u8 room_id[16];
    u8 scope[16];
    u8 own_node_info[UDS_RELAY_V3_NODE_INFO_SIZE];
    u8 host_raw_network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE];
    u8 host_raw_node_info[UDS_RELAY_V3_NODE_INFO_SIZE];
    u16 acquire_body_length;
    u8 acquire_body[0x148];
    UdsRelayV3Peers peers;
} RelayV3Role;

static RelayV3Role s_relayV3Role;
static RelayV3Role s_relayV3RetiringRole;
static u64 s_relayV3RoleCounter = 0;
static Handle s_relayV3BbpProcess = 0;
static u64 s_relayV3NextProcessPollMs = 0;

/* Each bind has its own receive ring and event, protected by s_connLock. */
#define MAX_BINDS 4u
typedef struct {
    bool   used;
    u32    bindNodeID;
    u8     channel;
    u16    srcNodeFilter;
    Handle event;
    volatile u32 freedTick;
    UdsRecvRingV3 ring;
} BindSlot;
static BindSlot s_binds[MAX_BINDS];

#define DLP_ADVERT_CHANNEL  1u

static BindSlot *bindByChannel(u8 channel)
{
    for (u32 i = 0; i < MAX_BINDS; i++)
        if (s_binds[i].used && s_binds[i].channel == channel) return &s_binds[i];
    return NULL;
}
static BindSlot *bindByNodeID(u32 bindNodeID)
{
    for (u32 i = 0; i < MAX_BINDS; i++)
        if (s_binds[i].used && s_binds[i].bindNodeID == bindNodeID) return &s_binds[i];
    return NULL;
}

static void relayReclaimFreedBinds(void)
{
    RecursiveLock_Lock(&s_connLock);
    for (u32 i = 0; i < MAX_BINDS; i++)
    {
        BindSlot *b = &s_binds[i];
        if (b->used || b->event == 0 || b->freedTick == 0) continue;
        u32 nowT = (u32)(svcGetSystemTick() >> 8);
        if ((u32)(nowT - b->freedTick) < 210000u) continue;
        svcSignalEvent(b->event);
        svcCloseHandle(b->event);
        b->event = 0;
        b->freedTick = 0;
    }
    RecursiveLock_Unlock(&s_connLock);
}

/* Relay socket I/O belongs to the relay thread; handlers enqueue sends. */
typedef struct __attribute__((aligned(4))) {
    u16 dst; u8 channel; u16 len; u32 sendGeneration;
    u8 data[RELAY_UDS_PAYLOAD_MAX];
} SendEntry;
#define SEND_RING_CAP 128u
static SendEntry s_sendRing[SEND_RING_CAP];
static volatile u32 s_sendWrite = 0; // producer: UDS service thread
static volatile u32 s_sendRead  = 0; // consumer: relay thread
static u32 s_sendGeneration = 1;

#define UDS_BEACON_SCAN_INTERVAL_NS (300LL * 1000LL * 1000LL)

/* Advert cache and seed state are protected by s_beaconLock. */
static UdsDlpAdvertCache s_dlpAdvertCache;
static bool s_dlpAdvertSeedValid = false;
static bool s_dlpAdvertSeedFailed = false;
static u8 s_dlpAdvertSeedHostMac[6];
static u32 s_dlpAdvertSeedValue = 0;
static bool s_dlpAdvertPrimed = false;
static u8 s_relayV3DlpAdvertSeedRoom[16];

static RecursiveLock s_beaconLock;
static bool s_beaconLockReady = false;

static void beaconLockInitOnce(void)
{
    if (!s_beaconLockReady)
    {
        RecursiveLock_Init(&s_beaconLock);
        s_beaconLockReady = true;
    }
}

static void dlpAdvertCacheClearLocked(void)
{
    udsDlpAdvertCacheReset(&s_dlpAdvertCache);
    s_dlpAdvertPrimed = false;
}

/* Caller holds s_beaconLock; Finalize clears fragments but retains the seed. */
static void relayV3DlpAdvertSelectionChangedLocked(void)
{
    dlpAdvertCacheClearLocked();
    s_dlpAdvertSeedValid = false;
    s_dlpAdvertSeedFailed = false;
    s_dlpAdvertSeedValue = 0;
    memset(s_dlpAdvertSeedHostMac, 0, sizeof(s_dlpAdvertSeedHostMac));
    memset(s_relayV3DlpAdvertSeedRoom, 0,
           sizeof(s_relayV3DlpAdvertSeedRoom));
}

static bool psFillDlpAdvertSeed(void *opaque, uint32_t size,
                                const uint8_t input[4], uint8_t output[4],
                                uint32_t algorithm, uint32_t key_type,
                                uint8_t ctr[16])
{
    Result initResult;
    Result aesResult = 0;
    (void)opaque;
    if (size != 4u || input == NULL || output == NULL || ctr == NULL ||
        algorithm != (uint32_t)PS_ALGORITHM_CTR_ENC ||
        key_type != (uint32_t)PS_KEYSLOT_39_DLP)
        return false;

    RecursiveLock_Lock(&s_psLock);
    initResult = psInit();
    if (R_SUCCEEDED(initResult))
    {
        aesResult = PS_EncryptDecryptAes(size, (u8 *)input, output,
                                         PS_ALGORITHM_CTR_ENC,
                                         PS_KEYSLOT_39_DLP, ctr);
        psExit();
    }
    RecursiveLock_Unlock(&s_psLock);
    return R_SUCCEEDED(initResult) && R_SUCCEEDED(aesResult);
}

static bool relayV3DlpAdvertSeedMatchesLocked(void)
{
    return s_relayV3SelectedRoom.valid && s_dlpAdvertSeedValid &&
           memcmp(s_relayV3DlpAdvertSeedRoom,
                  s_relayV3SelectedRoom.room_id, 16u) == 0 &&
           memcmp(s_dlpAdvertSeedHostMac,
                  s_relayV3SelectedRoom.network_info, 6u) == 0;
}

/* Run PS IPC without state locks, then revalidate the room and role. */
static bool relayV3DlpAdvertEnsureSeed(void)
{
    u8 room[16];
    u8 hostMac[6];
    u32 seed = 0;

    RecursiveLock_Lock(&s_connLock);
    RecursiveLock_Lock(&s_beaconLock);
    if (!s_relayV3SelectedRoom.valid || !s_isSpectator ||
        s_connStatus != UDS_STATUS_SPECTATOR || s_dlpAdvertSeedFailed)
    {
        RecursiveLock_Unlock(&s_beaconLock);
        RecursiveLock_Unlock(&s_connLock);
        return false;
    }
    if (relayV3DlpAdvertSeedMatchesLocked())
    {
        RecursiveLock_Unlock(&s_beaconLock);
        RecursiveLock_Unlock(&s_connLock);
        return true;
    }
    memcpy(room, s_relayV3SelectedRoom.room_id, sizeof(room));
    memcpy(hostMac, s_relayV3SelectedRoom.network_info, sizeof(hostMac));
    RecursiveLock_Unlock(&s_beaconLock);
    RecursiveLock_Unlock(&s_connLock);

    if (!udsDlpAdvertGenerateSeed(hostMac, psFillDlpAdvertSeed, NULL, &seed))
    {
        RecursiveLock_Lock(&s_beaconLock);
        if (s_relayV3SelectedRoom.valid &&
            memcmp(room, s_relayV3SelectedRoom.room_id, sizeof(room)) == 0 &&
            memcmp(hostMac, s_relayV3SelectedRoom.network_info,
                   sizeof(hostMac)) == 0)
            s_dlpAdvertSeedFailed = true;
        RecursiveLock_Unlock(&s_beaconLock);
        return false;
    }

    RecursiveLock_Lock(&s_connLock);
    RecursiveLock_Lock(&s_beaconLock);
    if (s_isSpectator && s_connStatus == UDS_STATUS_SPECTATOR &&
        s_relayV3SelectedRoom.valid &&
        memcmp(room, s_relayV3SelectedRoom.room_id, sizeof(room)) == 0 &&
        memcmp(hostMac, s_relayV3SelectedRoom.network_info,
               sizeof(hostMac)) == 0)
    {
        memcpy(s_relayV3DlpAdvertSeedRoom, room, sizeof(room));
        memcpy(s_dlpAdvertSeedHostMac, hostMac, sizeof(hostMac));
        s_dlpAdvertSeedValue = seed;
        s_dlpAdvertSeedValid = true;
        s_dlpAdvertSeedFailed = false;
        RecursiveLock_Unlock(&s_beaconLock);
        RecursiveLock_Unlock(&s_connLock);
        return true;
    }
    RecursiveLock_Unlock(&s_beaconLock);
    RecursiveLock_Unlock(&s_connLock);
    return false;
}

/* Caller holds s_connLock then s_beaconLock. Publish all five fragments together;
 * prejoin adverts use the selected room and host generation 1, not guest membership. */
static bool relayV3DlpAdvertPrimeBindLocked(BindSlot *b)
{
    uint16_t costs[UDS_DLP_ADVERT_FRAGMENT_COUNT];
    uint16_t needed = 0;
    u16 freeSlots;

    if (b == NULL || !b->used || b->channel != DLP_ADVERT_CHANNEL ||
        !s_isSpectator || s_connStatus != UDS_STATUS_SPECTATOR ||
        !relayV3DlpAdvertSeedMatchesLocked())
        return false;
    for (u8 i = 0; i < UDS_DLP_ADVERT_FRAGMENT_COUNT; ++i)
    {
        costs[i] = udsRecvRingSlotCost(s_dlpAdvertCache.lengths[i]);
        needed = (u16)(needed + costs[i]);
    }
    freeSlots = b->ring.ring.capacity_slots >= b->ring.ring.used_slots
        ? (u16)(b->ring.ring.capacity_slots - b->ring.ring.used_slots) : 0u;
    if (!udsDlpAdvertShouldPrime(udsDlpAdvertCacheComplete(&s_dlpAdvertCache),
                                 freeSlots, s_dlpAdvertPrimed) ||
        needed != 214u || !udsRecvRingCanReserve(&b->ring.ring, costs,
                                                 UDS_DLP_ADVERT_FRAGMENT_COUNT))
        return false;
    for (u8 i = 0; i < UDS_DLP_ADVERT_FRAGMENT_COUNT; ++i)
        if (!udsRecvRingV3PushCurrent(
                &b->ring, 1u, UDS_NODE_BROADCAST, DLP_ADVERT_CHANNEL,
                s_dlpAdvertCache.fragments[i], s_dlpAdvertCache.lengths[i],
                s_relayV3SelectedRoom.room_id,
                s_relayV3SelectedRoom.room_id, 1u, 1u,
                UDS_CONNECT_ROLE_SPECTATOR))
            return false;
    s_dlpAdvertPrimed = true;
    return true;
}

static bool relayV3DlpAdvertReceive(u8 flags, const u8 *body, u16 bodyLength)
{
    u8 room[16];
    u16 payloadLength;
    bool accepted;
    bool primed = false;
    Handle primeEvent = 0;

    RecursiveLock_Lock(&s_connLock);
    RecursiveLock_Lock(&s_beaconLock);
    accepted = s_isSpectator && s_connStatus == UDS_STATUS_SPECTATOR &&
               s_relayV3SelectedRoom.valid &&
               udsRelayV3PrejoinAdvertMatches(
                   flags, body, bodyLength, s_relayV3SelectedRoom.room_id);
    if (accepted)
        memcpy(room, s_relayV3SelectedRoom.room_id, sizeof(room));
    RecursiveLock_Unlock(&s_beaconLock);
    RecursiveLock_Unlock(&s_connLock);
    if (!accepted)
        return false;

    /* Consume matching prejoin packets even when PS is unavailable. */
    if (!relayV3DlpAdvertEnsureSeed())
        return true;

    payloadLength = (u16)body[22] | ((u16)body[23] << 8);
    RecursiveLock_Lock(&s_connLock);
    RecursiveLock_Lock(&s_beaconLock);
    accepted = s_isSpectator && s_connStatus == UDS_STATUS_SPECTATOR &&
               s_relayV3SelectedRoom.valid &&
               memcmp(room, s_relayV3SelectedRoom.room_id, sizeof(room)) == 0 &&
               relayV3DlpAdvertSeedMatchesLocked() &&
               udsRelayV3PrejoinAdvertMatches(
                   flags, body, bodyLength, s_relayV3SelectedRoom.room_id);
    if (accepted)
    {
        BindSlot *bind;
        accepted = udsDlpAdvertCacheAccept(&s_dlpAdvertCache, body + 32u,
                                           payloadLength,
                                           s_dlpAdvertSeedValue);
        if (accepted)
            udsDlpAdvertCacheValidate(&s_dlpAdvertCache,
                                      s_dlpAdvertSeedValue);
        bind = bindByChannel(DLP_ADVERT_CHANNEL);
        if (accepted && udsDlpAdvertCacheComplete(&s_dlpAdvertCache))
        {
            primed = relayV3DlpAdvertPrimeBindLocked(bind);
            if (primed && bind != NULL)
                primeEvent = bind->event;
        }
    }
    if (primed && primeEvent != 0)
        svcSignalEvent(primeEvent);
    RecursiveLock_Unlock(&s_beaconLock);
    RecursiveLock_Unlock(&s_connLock);
    return true;
}







static bool relayV3FileMissing(Result result)
{
    return R_FAILED(result) && R_MODULE(result) == RM_FS &&
           R_SUMMARY(result) == RS_NOTFOUND;
}

static bool relayV3ReadHost(u32 *outAddrBE, u16 *outPortBE)
{
    UdsBbpSnapshot config;
    u8 address[4];
    u16 port;
    UdsRedirect_GetBbpSnapshot(&config);
    if (!config.valid[config.selected])
        return false;
    if (config.selected == 0)
    {
        if (strcmp(config.endpoints[0], BBP_OFFICIAL_ENDPOINT) != 0)
            return false;
        /* Resolve the default host only after SOC starts. */
        *outAddrBE = 0;
        *outPortBE = htons(BBP_OFFICIAL_PORT);
        return true;
    }
    if (!udsRelayV3HostParse(config.endpoints[config.selected],
                             strlen(config.endpoints[config.selected]), address, &port))
        return false;
    *outAddrBE = htonl(((u32)address[0] << 24) | ((u32)address[1] << 16) |
                       ((u32)address[2] << 8) | address[3]);
    *outPortBE = htons(port);
    return true;
}

static bool bbpCanonicalHost(const char *value, u32 length, char out[BBP_ENDPOINT_SIZE])
{
    u8 address[4];
    u16 port;
    if (!udsRelayV3HostParse(value, length, address, &port))
        return false;
    sprintf(out, "%u.%u.%u.%u:%u", address[0], address[1], address[2], address[3], port);
    return true;
}

bool UdsRedirect_ResolveBbpEndpoint(const char *endpoint, u32 *address, u16 *port)
{
    if (endpoint == NULL || address == NULL || port == NULL)
        return false;
    u8 octets[4];
    u16 hostPort;
    if (udsRelayV3HostParse(endpoint, strlen(endpoint), octets, &hostPort))
    {
        *address = htonl(((u32)octets[0] << 24) | ((u32)octets[1] << 16) |
                         ((u32)octets[2] << 8) | octets[3]);
        *port = htons(hostPort);
        return true;
    }
    if (strcmp(endpoint, BBP_OFFICIAL_ENDPOINT) != 0 ||
        !miniSocResolveIPv4(BBP_OFFICIAL_HOST, address))
        return false;
    *port = htons(BBP_OFFICIAL_PORT);
    return true;
}

static void bbpLoadSettings(void)
{
    memset(&s_bbpConfig, 0, sizeof(s_bbpConfig));
    s_bbpConfig.selected = 0;
    strcpy(s_bbpConfig.endpoints[0], BBP_OFFICIAL_ENDPOINT);
    s_bbpConfig.valid[0] = true;
    bool customOneStored = false;
    for (u8 slot = 1; slot < 4; slot++)
    {
        IFile file;
        char value[64];
        u64 size = 0, read = 0;
        strcpy(s_bbpConfig.endpoints[slot], "192.168.0.0:24873");
        Result result = IFile_Open(&file, ARCHIVE_SDMC, fsMakePath(PATH_EMPTY, ""),
                                    fsMakePath(PATH_ASCII, s_bbpPresetPaths[slot]), FS_OPEN_READ);
        if (R_FAILED(result))
        {
            s_bbpConfig.valid[slot] = relayV3FileMissing(result);
            continue;
        }
        result = IFile_GetSize(&file, &size);
        if (R_SUCCEEDED(result) && size > 0 && size <= sizeof(value))
            result = IFile_Read(&file, &read, value, (u32)size);
        IFile_Close(&file);
        s_bbpConfig.valid[slot] = R_SUCCEEDED(result) && size > 0 &&
            size <= sizeof(value) && read == size &&
            bbpCanonicalHost(value, (u32)size, s_bbpConfig.endpoints[slot]);
        if (slot == 1)
            customOneStored = s_bbpConfig.valid[slot];
    }
    if (customOneStored)
        s_bbpConfig.selected = 1;
    IFile selectedFile;
    char value[8];
    u64 size = 0, read = 0;
    Result result = IFile_Open(&selectedFile, ARCHIVE_SDMC, fsMakePath(PATH_EMPTY, ""),
                                fsMakePath(PATH_ASCII, BBP_PATH_SELECTED), FS_OPEN_READ);
    s_bbpSelectionValid = relayV3FileMissing(result);
    if (R_SUCCEEDED(result))
    {
        result = IFile_GetSize(&selectedFile, &size);
        if (R_SUCCEEDED(result) && size > 0 && size <= sizeof(value))
            result = IFile_Read(&selectedFile, &read, value, (u32)size);
        IFile_Close(&selectedFile);
        s_bbpSelectionValid = R_SUCCEEDED(result) && size > 0 &&
            size <= sizeof(value) && read == size && value[0] >= '0' && value[0] <= '3';
        for (u32 i = 1; s_bbpSelectionValid && i < size; i++)
            s_bbpSelectionValid = value[i] == '\n' || value[i] == '\r' || value[i] == ' ';
        if (s_bbpSelectionValid)
        {
            u8 selected = (u8)(value[0] - '0');
            s_bbpSelectionValid = s_bbpConfig.valid[selected];
            if (s_bbpSelectionValid)
                s_bbpConfig.selected = selected;
        }
    }
}

bool UdsRedirect_CanChangeBbpConfig(void)
{
    FS_ProgramInfo info;
    u32 pid = 0, flags = 0;
    Result result = PMDBG_GetCurrentAppInfo(&info, &pid, &flags);
    // PM reports no running application with this result.
    if (result == MAKERESULT(RL_TEMPORARY, RS_NOTFOUND, RM_PM, 0x100))
        return true;
    return R_SUCCEEDED(result) && info.programId != UINT64_C(0x00040000000A0B00);
}

void UdsRedirect_GetBbpSnapshot(UdsBbpSnapshot *out)
{
    if (out == NULL) return;
    u64 now = svcGetSystemTick() / ((u64)SYSCLOCK_ARM11 / 1000u);
    RecursiveLock_Lock(&s_connLock);
    *out = s_bbpConfig;
    out->enabled = s_proxyEnabled;
    out->generation = s_proxyConfigGeneration;
    out->configStatus = s_proxyConfigStatus;
    bool current = s_bbpHealthGeneration == out->generation && out->enabled &&
                   out->configStatus == UDS_PROXY_CONFIG_OK;
    out->connected = current && s_bbpConfirmed &&
                     !udsRelayV3DeadlineExpired(s_bbpLastRxMs, now);
    out->connecting = current && !out->connected && s_bbpSocketOpen &&
                      !udsRelayV3DeadlineExpired(s_bbpStartedMs, now);
    RecursiveLock_Unlock(&s_connLock);
}

static void bbpConfigChangedLocked(void)
{
    if (++s_proxyConfigGeneration == 0u) s_proxyConfigGeneration = 1u;
    if (s_proxyConfigStatus == UDS_PROXY_CONFIG_NAMESPACE)
        s_proxyConfigStatus = UDS_PROXY_CONFIG_OK;
}

u32 UdsRedirect_SetBbpMatchmaking(u8 channel, u16 pin)
{
    if (channel > 4 || pin > 9999) return BBP_CONFIG_INVALID;
    if (!UdsRedirect_CanChangeBbpConfig()) return BBP_CONFIG_BUSY;
    RecursiveLock_Lock(&s_connLock);
    bool changed = pin != s_bbpConfig.pin || (pin == 0 && channel != s_bbpConfig.channel);
    s_bbpConfig.channel = channel;
    s_bbpConfig.pin = pin;
    if (changed) bbpConfigChangedLocked();
    RecursiveLock_Unlock(&s_connLock);
    return BBP_CONFIG_OK;
}

/* Delete + rename leaves a gap in which the target may be absent. */
static bool bbpWriteBytesAtomic(const char *path, const u8 *bytes, u32 length)
{
    char temp[64];
    if (path == NULL || bytes == NULL || strlen(path) + 5u > sizeof(temp))
        return false;
    strcpy(temp, path);
    strcat(temp, ".tmp");
    FS_Archive archive;
    Result result = FSUSER_OpenArchive(&archive, ARCHIVE_SDMC,
                                       fsMakePath(PATH_EMPTY, ""));
    if (R_FAILED(result)) return false;
    (void)FSUSER_CreateDirectory(archive, fsMakePath(PATH_ASCII, "/luma/bbpproxy"), 0);
    IFile file;
    result = IFile_Open(&file, ARCHIVE_SDMC, fsMakePath(PATH_EMPTY, ""),
                        fsMakePath(PATH_ASCII, temp), FS_OPEN_CREATE | FS_OPEN_WRITE);
    if (R_SUCCEEDED(result))
    {
        u64 written = 0;
        result = IFile_SetSize(&file, 0);
        if (R_SUCCEEDED(result))
            result = IFile_Write(&file, &written, bytes, length, FS_WRITE_FLUSH);
        IFile_Close(&file);
        if (R_SUCCEEDED(result) && written == length)
        {
            (void)FSUSER_DeleteFile(archive, fsMakePath(PATH_ASCII, path));
            result = FSUSER_RenameFile(archive, fsMakePath(PATH_ASCII, temp),
                                       archive, fsMakePath(PATH_ASCII, path));
            if (R_FAILED(result))
                (void)FSUSER_DeleteFile(archive, fsMakePath(PATH_ASCII, temp));
            FSUSER_CloseArchive(archive);
            return R_SUCCEEDED(result);
        }
    }
    (void)FSUSER_DeleteFile(archive, fsMakePath(PATH_ASCII, temp));
    FSUSER_CloseArchive(archive);
    return false;
}

static bool bbpWriteSetting(const char *path, const char *value)
{
    return value != NULL &&
           bbpWriteBytesAtomic(path, (const u8 *)value, (u32)strlen(value));
}

u32 UdsRedirect_SetBbpEndpoint(u8 slot, const char *value)
{
    if (slot > 3 || (slot == 0 && value != NULL)) return BBP_CONFIG_INVALID;
    if (!UdsRedirect_CanChangeBbpConfig()) return BBP_CONFIG_BUSY;
    char canonical[BBP_ENDPOINT_SIZE];
    UdsBbpSnapshot old;
    UdsRedirect_GetBbpSnapshot(&old);
    if (value != NULL)
    {
        if (!bbpCanonicalHost(value, strlen(value), canonical)) return BBP_CONFIG_INVALID;
        if (!bbpWriteSetting(s_bbpPresetPaths[slot], canonical)) return BBP_CONFIG_SAVE_FAILED;
    }
    else
    {
        if (!old.valid[slot]) return BBP_CONFIG_INVALID;
        strcpy(canonical, old.endpoints[slot]);
    }
    char index[2] = {(char)('0' + slot), 0};
    bool selected = (old.selected == slot && s_bbpSelectionValid) ||
                    bbpWriteSetting(BBP_PATH_SELECTED, index);
    RecursiveLock_Lock(&s_connLock);
    if (value != NULL)
    {
        strcpy(s_bbpConfig.endpoints[slot], canonical);
        s_bbpConfig.valid[slot] = true;
    }
    if (selected)
    {
        bool changed = old.selected != slot || !s_bbpSelectionValid ||
                       !old.valid[slot] || strcmp(old.endpoints[slot], canonical) != 0;
        s_bbpConfig.selected = slot;
        s_bbpSelectionValid = true;
        s_proxyConfigStatus = UDS_PROXY_CONFIG_OK;
        if (changed) bbpConfigChangedLocked();
    }
    RecursiveLock_Unlock(&s_connLock);
    return selected ? BBP_CONFIG_OK :
           value != NULL ? BBP_CONFIG_PRESET_SAVED : BBP_CONFIG_SAVE_FAILED;
}

static bool relayV3GenerateUuid(u8 identifier[16])
{
    Result initResult;
    Result randomResult = 0;
    RecursiveLock_Lock(&s_psLock);
    initResult = psInit();
    if (R_SUCCEEDED(initResult))
    {
        randomResult = PS_GenerateRandomBytes(identifier, 16);
        psExit();
    }
    RecursiveLock_Unlock(&s_psLock);
    return R_SUCCEEDED(initResult) && R_SUCCEEDED(randomResult) &&
           udsRelayV3UuidV4Prepare(identifier) && udsRelayV3UuidV4Valid(identifier);
}

bool UdsRedirect_GenerateProbeNonce(u8 nonce[8])
{
    u8 identifier[16];
    if (nonce == NULL || !relayV3GenerateUuid(identifier)) return false;
    memcpy(nonce, identifier, 8);
    return true;
}

bool UdsRedirect_GenerateV4Key(u8 key[32])
{
    Result initResult;
    Result randomResult = 0;
    if (key == NULL) return false;
    RecursiveLock_Lock(&s_psLock);
    initResult = psInit();
    if (R_SUCCEEDED(initResult))
    {
        randomResult = PS_GenerateRandomBytes(key, 32);
        psExit();
    }
    RecursiveLock_Unlock(&s_psLock);
    return R_SUCCEEDED(initResult) && R_SUCCEEDED(randomResult);
}

static bool relayV3ReadOrCreateClientId(void)
{
    u8 value[16];
    IFile file;
    Result openResult = IFile_Open(
        &file, ARCHIVE_SDMC, fsMakePath(PATH_EMPTY, ""),
        fsMakePath(PATH_ASCII, RELAY_V3_PATH_CLIENT_ID), FS_OPEN_READ);
    if (R_SUCCEEDED(openResult))
    {
        u64 size = 0;
        u64 total = 0;
        bool sized = false;
        Result result = IFile_GetSize(&file, &size);
        sized = R_SUCCEEDED(result) && size == sizeof(value);
        if (sized)
            result = IFile_Read(&file, &total, value, sizeof(value));
        IFile_Close(&file);
        if (sized && R_SUCCEEDED(result) && total == sizeof(value) &&
            udsRelayV3UuidV4Valid(value))
        {
            memcpy(s_relayV3ClientId, value, sizeof(s_relayV3ClientId));
            return true;
        }
        /* Do not overwrite a possibly valid ID on a transient or short read. */
        if (R_FAILED(result) || (sized && total != sizeof(value)))
            return false;
    }
    else if (!relayV3FileMissing(openResult))
    {
        return false;
    }
    if (!relayV3GenerateUuid(value))
        return false;

    if (!bbpWriteBytesAtomic(RELAY_V3_PATH_CLIENT_ID, value,
                             sizeof(s_relayV3ClientId)))
        return false;
    memcpy(s_relayV3ClientId, value, sizeof(s_relayV3ClientId));
    return true;
}

static void bbpSetConfigStatus(u32 status)
{
    RecursiveLock_Lock(&s_connLock);
    s_proxyConfigStatus = status;
    RecursiveLock_Unlock(&s_connLock);
}

static bool relayV3ValidateConfig(void)
{
    u32 address;
    u16 port;
    if (!s_bbpSelectionValid)
    {
        bbpSetConfigStatus(UDS_PROXY_CONFIG_SELECTION);
        return false;
    }
    if (!relayV3ReadHost(&address, &port))
    {
        bbpSetConfigStatus(UDS_PROXY_CONFIG_RELAY_HOST);
        return false;
    }
    if (!relayV3ReadOrCreateClientId())
    {
        bbpSetConfigStatus(UDS_PROXY_CONFIG_CLIENT_ID);
        return false;
    }
    bbpSetConfigStatus(UDS_PROXY_CONFIG_OK);
    return true;
}

static bool bbpSetKernelRedirectEnabled(bool enabled)
{
    s64 result = 0;
    Result svcResult = svcGetSystemInfo(&result, 0x10000,
                                        enabled ? 0x310 : 0x311);
    return R_SUCCEEDED(svcResult) && result == (enabled ? 1 : 0);
}

void UdsRedirect_LoadConfig(void)
{
    connLockInitOnce();
    psLockInitOnce();
    beaconLockInitOnce();
    bbpLoadSettings();
    s_proxyEnabled = false;
    if (!bbpSetKernelRedirectEnabled(false))
    {
        s_proxyConfigStatus = UDS_PROXY_CONFIG_REDIRECT;
        return;
    }
    s_proxyConfigStatus = UDS_PROXY_CONFIG_OK;
}

bool UdsRedirect_SetProxyEnabled(bool enabled)
{
    if (enabled && !UdsRedirect_CanChangeBbpConfig())
        return false;
    bool changed = s_proxyEnabled != enabled;
    if (enabled)
    {
        if (!relayV3ValidateConfig())
            return false;
    }
    if (!bbpSetKernelRedirectEnabled(enabled))
    {
        RecursiveLock_Lock(&s_connLock);
        s_proxyEnabled = false;
        s_proxyConfigStatus = UDS_PROXY_CONFIG_REDIRECT;
        if (changed)
        {
            s_proxyConfigGeneration++;
            if (s_proxyConfigGeneration == 0u)
                s_proxyConfigGeneration = 1u;
        }
        RecursiveLock_Unlock(&s_connLock);
        return false;
    }
    RecursiveLock_Lock(&s_connLock);
    s_proxyEnabled = enabled;
    s_proxyConfigStatus = UDS_PROXY_CONFIG_OK;
    if (changed)
    {
        s_proxyConfigGeneration++;
        if (s_proxyConfigGeneration == 0u)
            s_proxyConfigGeneration = 1u;
    }
    RecursiveLock_Unlock(&s_connLock);
    return true;
}

bool UdsRedirect_IsProxyEnabled(void)
{
    return s_proxyEnabled;
}

u32 UdsRedirect_GetProxyConfigStatus(void)
{
    return s_proxyConfigStatus;
}

static u64 relayV3NowMs(void)
{
    return svcGetSystemTick() / ((u64)SYSCLOCK_ARM11 / 1000u);
}

static u16 relayV3Load16(const u8 *data)
{
    return (u16)data[0] | ((u16)data[1] << 8);
}

static u32 relayV3Load32(const u8 *data)
{
    return (u32)data[0] | ((u32)data[1] << 8) |
           ((u32)data[2] << 16) | ((u32)data[3] << 24);
}

static u64 relayV3Load64(const u8 *data)
{
    return (u64)relayV3Load32(data) | ((u64)relayV3Load32(data + 4u) << 32);
}

static void relayV3Store16(u8 *data, u16 value)
{
    data[0] = (u8)value;
    data[1] = (u8)(value >> 8);
}

static void relayV3Store32(u8 *data, u32 value)
{
    for (u8 i = 0; i < 4u; i++) data[i] = (u8)(value >> (8u * i));
}

static void relayV3Store64(u8 *data, u64 value)
{
    for (u8 i = 0; i < 8u; i++) data[i] = (u8)(value >> (8u * i));
}

/* A process handle signals on exit, not when HOME takes foreground focus. */
static bool relayV3BbpExited(u64 nowMs)
{
    FS_ProgramInfo programInfo;
    u32 pid = 0;
    u32 launchFlags = 0;
    if (nowMs < s_relayV3NextProcessPollMs)
        return false;
    s_relayV3NextProcessPollMs = nowMs + 1000u;
    if (s_relayV3BbpProcess != 0)
    {
        if (svcWaitSynchronization(s_relayV3BbpProcess, 0) != 0)
            return false;
        svcCloseHandle(s_relayV3BbpProcess);
        s_relayV3BbpProcess = 0;
        return true;
    }
    if (R_SUCCEEDED(PMDBG_GetCurrentAppInfo(&programInfo, &pid,
                                             &launchFlags)) &&
        programInfo.programId == UINT64_C(0x00040000000A0B00))
    {
        Handle process = 0;
        if (R_SUCCEEDED(svcOpenProcess(&process, pid)))
            s_relayV3BbpProcess = process;
    }
    return false;
}

static bool relayV3TokenReady(void)
{
    static const u8 zero[16] = {0};
    return memcmp(s_relayV3Token, zero, sizeof(zero)) != 0;
}

static void relayV3SocketClose(void)
{
    udsRelayV4ClientClear(&s_relayV4Client);
    if (s_relayV3Confirmed)
    {
        s_relayV3StartedMs = s_relayV3LastRxMs;
        s_relayV3Confirmed = false;
        s_relayV3RetryAttempt = 0;
        s_relayV3NextSendMs = relayV3NowMs();
    }
    if (s_relaySock >= 0)
    {
        socClose(s_relaySock);
        s_relaySock = -1;
    }
    if (s_relayUp)
    {
        miniSocExit();
        s_relayUp = false;
    }
}

static void relayV3RetireLocal(void)
{
    RecursiveLock_Lock(&s_connLock);
    RecursiveLock_Lock(&s_beaconLock);
    s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
    s_joinAttemptSerial++;
    s_wantJoin = false;
    s_joinInFlight = false;
    s_connected = false;
    s_isSpectator = false;
    connResetVisibleLocked();
    relayV3DlpAdvertSelectionChangedLocked();
    memset(&s_relayV3Role, 0, sizeof(s_relayV3Role));
    memset(&s_relayV3RetiringRole, 0, sizeof(s_relayV3RetiringRole));
    memset(s_relayV3Scope, 0, sizeof(s_relayV3Scope));
    s_relayV3RosterVersion = 0;
    memset(&s_relayV3Rooms, 0, sizeof(s_relayV3Rooms));
    memset(&s_relayV3SelectedRoom, 0, sizeof(s_relayV3SelectedRoom));
    s_relayV3SelectedRole = 0;
    s_relayV3RoomListLastValidMs = 0;
    if (s_connEvent)
        svcSignalEvent(s_connEvent);
    RecursiveLock_Unlock(&s_beaconLock);
    RecursiveLock_Unlock(&s_connLock);
}

/* Caller holds s_connLock; retire ACKs must not block a new role. */
static bool relayV3ScheduleRetireLocked(u8 packetType, u8 reason, u64 nowMs)
{
    if ((packetType == UDS_RELAY_V3_PKT_ROOM_CLOSE &&
         s_relayV3Role.kind != RELAY_V3_ROLE_HOST) ||
        (packetType == UDS_RELAY_V3_PKT_LEAVE &&
         s_relayV3Role.kind != RELAY_V3_ROLE_GUEST) ||
        s_relayV3Role.epoch == 0u)
        return false;
    s_relayV3RetiringRole = s_relayV3Role;
    s_relayV3RetiringRole.retire_type = packetType;
    s_relayV3RetiringRole.retire_reason = reason;
    s_relayV3RetiringRole.retire_pending = true;
    s_relayV3RetiringRole.pending = false;
    s_relayV3RetiringRole.active = false;
    s_relayV3RetiringRole.started_ms = nowMs;
    s_relayV3RetiringRole.next_send_ms = nowMs;
    s_relayV3RetiringRole.retry_attempt = 0;
    memset(&s_relayV3Role, 0, sizeof(s_relayV3Role));
    memset(s_relayV3Scope, 0, sizeof(s_relayV3Scope));
    s_relayV3RosterVersion = 0;
    s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
    s_wantJoin = false;
    s_joinInFlight = false;
    s_connected = false;
    s_isSpectator = false;
    connResetVisibleLocked();
    if (s_connEvent)
        svcSignalEvent(s_connEvent);
    return true;
}

static bool relayV3StartRegistration(u64 nowMs)
{
    memset(s_relayV3Token, 0, sizeof(s_relayV3Token));
    RecursiveLock_Lock(&s_connLock);
    if (s_relayV3Role.kind == RELAY_V3_ROLE_NONE &&
        s_relayV3RetiringRole.kind == RELAY_V3_ROLE_NONE)
    {
        memset(s_relayV3Scope, 0, sizeof(s_relayV3Scope));
        s_relayV3RosterVersion = 0;
        s_relayV3RoleCounter = 0;
    }
    RecursiveLock_Unlock(&s_connLock);
    s_relayV3FragmentId = 1u;
    s_relayV3Confirmed = false;
    s_relayV3RetryAttempt = 0;
    s_relayV3StartedMs = nowMs;
    s_relayV3NextSendMs = nowMs;
    return relayV3GenerateUuid(s_relayV3Nonce);
}

static bool relayV4SendHello(void)
{
    size_t length = 0u;
    return udsRelayV4ClientHello(&s_relayV4Client, s_relayV4Tx,
                                 sizeof(s_relayV4Tx), &length) &&
           socSend(s_relaySock, s_relayV4Tx, length, 0) == (int)length;
}

static bool relayV4StartHandshake(void)
{
    u8 privateKey[32];
    udsRelayV4ClientClear(&s_relayV4Client);
    if (!UdsRedirect_GenerateV4Key(privateKey) ||
        !udsRelayV4ClientInit(&s_relayV4Client, privateKey))
    {
        memset(privateKey, 0, sizeof(privateKey));
        return false;
    }
    memset(privateKey, 0, sizeof(privateKey));
    return relayV4SendHello();
}

static bool relayV3SendMessage(u8 packetType, u8 flags, const u8 token[16],
                               const u8 *body, u16 bodyLength)
{
    u8 count = 0;
    u32 fragmentId = bodyLength > UDS_RELAY_V3_MAX_FRAGMENT_BODY
        ? s_relayV3FragmentId : 0u;
    if (!udsRelayV4ClientReady(&s_relayV4Client) ||
        !udsRelayV3MessageEncode(packetType, flags, token, body, bodyLength,
                                 fragmentId, s_relayV3Tx,
                                 s_relayV3TxLengths, &count))
        return false;
    for (u8 i = 0; i < count; i++)
    {
        size_t encryptedLength = 0u;
        if (!udsRelayV4ClientEncrypt(&s_relayV4Client,
                                     s_relayV3Tx[i], s_relayV3TxLengths[i],
                                     s_relayV4Tx, sizeof(s_relayV4Tx),
                                     &encryptedLength) ||
            socSend(s_relaySock, s_relayV4Tx, encryptedLength, 0) !=
            (int)encryptedLength)
            return false;
    }
    if (count > 1u)
    {
        if (s_relayV3FragmentId == UINT32_MAX)
        {
            relayV3RetireLocal();
            return relayV3StartRegistration(relayV3NowMs());
        }
        s_relayV3FragmentId++;
    }
    return true;
}

static bool relayV3SendRegister(void)
{
    u8 body[0x30];
    return udsRelayV3RegisterBodyBuild(body, s_relayV3ClientId,
                                       s_relayV3Nonce, s_relayV3Channel, s_relayV3Pin) &&
           relayV3SendMessage(UDS_RELAY_V3_PKT_REGISTER, 0u,
                              (const u8 *)UDS_RELAY_V3_ADMISSION_MARKER,
                              body, sizeof(body));
}

static bool relayV3SendHeartbeat(void)
{
    u8 body[0x18];
    u8 scope[16];
    u32 rosterVersion;
    RecursiveLock_Lock(&s_connLock);
    memcpy(scope, s_relayV3Scope, sizeof(scope));
    rosterVersion = s_relayV3RosterVersion;
    RecursiveLock_Unlock(&s_connLock);
    return relayV3TokenReady() &&
           udsRelayV3HeartbeatBodyBuild(body, scope, rosterVersion) &&
           relayV3SendMessage(UDS_RELAY_V3_PKT_HEARTBEAT, 0u,
                              s_relayV3Token, body, sizeof(body));
}

static bool relayV3ReadMac(u8 mac[6])
{
    u8 value[8] = {0};
    socklen_t length = sizeof(value);
    if (miniSocGetNetworkOpt(SOL_CONFIG, NETOPT_MAC_ADDRESS,
                             value, &length) != 0 || length < 6u)
        return false;
    memcpy(mac, value, 6u);
    return true;
}

static bool relayV3PrepareHostRole(void)
{
    u64 epoch;
    u8 mac[6];

    RecursiveLock_Lock(&s_connLock);
    if (s_relayV3Role.kind != RELAY_V3_ROLE_HOST ||
        !s_relayV3Role.pending || s_relayV3Role.retire_pending ||
        s_relayV3Role.host_descriptor_prepared)
    {
        RecursiveLock_Unlock(&s_connLock);
        return true;
    }
    epoch = s_relayV3Role.epoch;
    RecursiveLock_Unlock(&s_connLock);

    if (!relayV3ReadMac(mac))
        return false;

    RecursiveLock_Lock(&s_connLock);
    if (s_relayV3Role.kind != RELAY_V3_ROLE_HOST ||
        !s_relayV3Role.pending || s_relayV3Role.retire_pending ||
        s_relayV3Role.epoch != epoch)
    {
        RecursiveLock_Unlock(&s_connLock);
        return true;
    }
    if (!s_relayV3Role.host_descriptor_prepared)
        s_relayV3Role.host_descriptor_prepared =
            udsRelayV3HostDescriptorPrepare(
                s_relayV3Role.acquire_body + 0x18u,
                s_relayV3Role.acquire_body + 0x120u, mac);
    bool prepared = s_relayV3Role.host_descriptor_prepared;
    RecursiveLock_Unlock(&s_connLock);
    return prepared;
}

/* Caller holds s_connLock and the current role has a validated peer map. */
static void relayV3PublishPeersLocked(bool first, u16 changed)
{
    s_ourNodeID = s_relayV3Role.peers.local_node;
    s_connected = true;
    s_wantJoin = false;
    s_joinInFlight = false;
    if (s_relayV3Role.kind == RELAY_V3_ROLE_GUEST)
    {
        s_hosting = false;
        s_isSpectator = false;
        s_sessionId = RELAY_NATIVE_SESSION_ID;
        s_connStatus = UDS_STATUS_CLIENT;
        s_connReason = UDS_REASON_ESTABLISHED;
    }
    /* cmd1D already published host self; filling the peer cache is not a rejoin. */
    if (s_relayV3Role.kind == RELAY_V3_ROLE_HOST)
        changed &= (u16)~1u;
    s_connChanged |= changed;
    s_connNodeMask = s_relayV3Role.peers.valid_mask;
    if ((first || changed != 0u) && s_connEvent)
        svcSignalEvent(s_connEvent);
}

static bool relayV3ApplyPeerMap(const u8 *body, u16 bodyLength)
{
    bool accepted = false;
    u16 changed = 0;

    RecursiveLock_Lock(&s_connLock);
    if ((s_relayV3Role.kind == RELAY_V3_ROLE_HOST ||
         s_relayV3Role.kind == RELAY_V3_ROLE_GUEST) &&
        (s_relayV3Role.pending || s_relayV3Role.active) &&
        !s_relayV3Role.retire_pending &&
        (s_relayV3Role.kind == RELAY_V3_ROLE_HOST
             ? relayV3Load16(body + 32u) == 1u &&
               memcmp(s_relayV3Role.room_id, s_relayV3Role.scope, 16u) == 0
             : relayV3Load16(body + 32u) != 1u &&
               memcmp(s_relayV3Role.room_id, s_relayV3Role.scope, 16u) != 0) &&
        udsRelayV3PeersApply(&s_relayV3Role.peers, body, bodyLength,
                             s_relayV3Role.room_id,
                             s_relayV3Role.scope,
                             s_relayV3Role.own_node_info,
                             s_relayV3Role.max_nodes, &changed))
    {
        bool first = !s_relayV3Role.active;
        bool guest = s_relayV3Role.kind == RELAY_V3_ROLE_GUEST;
        bool publish = guest
            ? (s_wantJoin ||
               (s_connStatus == UDS_STATUS_CLIENT &&
                s_connReason == UDS_REASON_ESTABLISHED))
            : s_relayV3Role.active && s_connStatus == UDS_STATUS_HOST;
        if (guest)
        {
            s_relayV3Role.pending = false;
            s_relayV3Role.active = true;
            memset(&s_relayV3RetiringRole, 0,
                   sizeof(s_relayV3RetiringRole));
        }
        s_relayV3Role.retry_attempt = 0;
        if (s_relayV3Role.active)
        {
            memcpy(s_relayV3Scope, s_relayV3Role.scope,
                   sizeof(s_relayV3Scope));
            s_relayV3RosterVersion = s_relayV3Role.peers.roster_version;
        }
        if (publish)
            relayV3PublishPeersLocked(first, changed);
        accepted = true;
    }
    RecursiveLock_Unlock(&s_connLock);
    return accepted;
}

static bool relayV3ReceiveJoinedData(u8 flags, const u8 *body, u16 bodyLength)
{
    bool accepted = false;
    u16 src = relayV3Load16(body + 16u);
    u16 dst = relayV3Load16(body + 18u);
    u8 channel = body[20];
    u16 payloadLength = relayV3Load16(body + 22u);
    u32 generation = relayV3Load32(body + 28u);

    RecursiveLock_Lock(&s_connLock);
    if (s_relayV3Role.active && !s_relayV3Role.retire_pending &&
        udsSendRouteCanTransmit(s_connStatus, s_connReason,
                                s_ourNodeID, s_sessionId) &&
        memcmp(body, s_relayV3Role.scope, 16u) == 0 &&
        src >= 1u && src <= 16u &&
        (s_relayV3Role.peers.valid_mask &
         (u16)(1u << (src - 1u))) != 0u &&
        generation == s_relayV3Role.peers.node_generations[src - 1u] &&
        (dst == UDS_NODE_BROADCAST || dst == s_ourNodeID))
    {
        BindSlot *bind = bindByChannel(channel);
        if (bind != NULL &&
            (bind->srcNodeFilter == UDS_NODE_BROADCAST ||
             bind->srcNodeFilter == src) &&
            udsRecvRingV3PushCurrent(
                &bind->ring, src, dst, channel, body + 32u, payloadLength,
                body, s_relayV3Role.scope, generation,
                s_relayV3Role.peers.node_generations[src - 1u],
                UDS_CONNECT_ROLE_CLIENT))
        {
            accepted = true;
            if (bind->event != 0)
                svcSignalEvent(bind->event);
        }
    }
    RecursiveLock_Unlock(&s_connLock);
    (void)flags;
    (void)bodyLength;
    return accepted;
}

static bool relayV3RetryIdConflict(const u8 *errorBody, u64 nowMs)
{
    u8 identifier[16];
    u64 epoch;
    u8 scope[16];
    u8 requestType = errorBody[4];

    RecursiveLock_Lock(&s_connLock);
    bool eligible = s_relayV3Role.pending &&
        !s_relayV3Role.id_conflict_retried &&
        requestType == s_relayV3Role.acquire_type &&
        memcmp(errorBody + 8u, s_relayV3Role.scope, 16u) == 0 &&
        s_relayV3RoleCounter != UINT64_MAX;
    epoch = s_relayV3Role.epoch;
    memcpy(scope, s_relayV3Role.scope, sizeof(scope));
    RecursiveLock_Unlock(&s_connLock);
    if (!eligible || !relayV3GenerateUuid(identifier))
        return false;

    RecursiveLock_Lock(&s_connLock);
    eligible = s_relayV3Role.pending &&
        !s_relayV3Role.id_conflict_retried &&
        s_relayV3Role.epoch == epoch &&
        requestType == s_relayV3Role.acquire_type &&
        memcmp(scope, s_relayV3Role.scope, sizeof(scope)) == 0 &&
        s_relayV3RoleCounter != UINT64_MAX;
    if (eligible)
    {
        s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
        s_relayV3Role.id_conflict_retried = true;
        s_relayV3Role.epoch = ++s_relayV3RoleCounter;
        relayV3Store64(s_relayV3Role.acquire_body,
                       s_relayV3Role.epoch);
        memcpy(s_relayV3Role.scope, identifier, sizeof(identifier));
        if (s_relayV3Role.kind == RELAY_V3_ROLE_HOST)
        {
            memcpy(s_relayV3Role.room_id, identifier, sizeof(identifier));
            memcpy(s_relayV3Role.acquire_body + 8u, identifier,
                   sizeof(identifier));
        }
        else
        {
            memcpy(s_relayV3Role.acquire_body + 24u, identifier,
                   sizeof(identifier));
        }
        memset(&s_relayV3Role.peers, 0, sizeof(s_relayV3Role.peers));
        s_relayV3Role.started_ms = nowMs;
        s_relayV3Role.next_send_ms = nowMs;
        s_relayV3Role.retry_attempt = 0;
    }
    RecursiveLock_Unlock(&s_connLock);
    return eligible;
}

static bool relayV3HandleMessage(u64 nowMs)
{
    UdsRelayV3Message *message = &s_relayV3Message;
    static const u8 zeroToken[16] = {0};
    if (!udsRelayV3BodyValidate(message->header.packet_type,
                                message->header.flags, message->body,
                                message->body_length))
        return false;

    if (message->header.packet_type == UDS_RELAY_V3_PKT_REGISTER_ACK &&
        !relayV3TokenReady() &&
        memcmp(message->header.token, zeroToken, sizeof(zeroToken)) != 0 &&
        memcmp(message->header.token, UDS_RELAY_V3_ADMISSION_MARKER, 16u) != 0 &&
        memcmp(message->body, s_relayV3Nonce, sizeof(s_relayV3Nonce)) == 0)
    {
        memcpy(s_relayV3Token, message->header.token, sizeof(s_relayV3Token));
        s_relayV3RetryAttempt = 0;
        s_relayV3NextSendMs = nowMs;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_ERROR &&
        !relayV3TokenReady() &&
        memcmp(message->header.token, UDS_RELAY_V3_ADMISSION_MARKER, 16u) == 0 &&
        (relayV3Load32(message->body) == 2u || relayV3Load32(message->body) == 9u) &&
        message->body[4] == UDS_RELAY_V3_PKT_REGISTER &&
        memcmp(message->body + 8u, s_relayV3Nonce, 16u) == 0)
    {
        RecursiveLock_Lock(&s_connLock);
        if (relayV3Load32(message->body) == 9u &&
            s_relayV3ConfigGeneration == s_proxyConfigGeneration)
            s_proxyConfigStatus = UDS_PROXY_CONFIG_NAMESPACE;
        RecursiveLock_Unlock(&s_connLock);
        return true;
    }
    if (!relayV3TokenReady() ||
        memcmp(message->header.token, s_relayV3Token,
               sizeof(s_relayV3Token)) != 0)
        return false;

    if (message->header.packet_type == UDS_RELAY_V3_PKT_HEARTBEAT)
    {
        bool current;
        RecursiveLock_Lock(&s_connLock);
        current = s_relayV3Role.active &&
                  memcmp(message->body, s_relayV3Role.scope, 16u) == 0 &&
                  relayV3Load32(message->body + 16u) ==
                      s_relayV3Role.peers.roster_version;
        RecursiveLock_Unlock(&s_connLock);
        if (!current)
            return false;
        s_relayV3Confirmed = true;
        s_relayV3LastRxMs = nowMs;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_PATH_CHALLENGE)
    {
        if (!relayV3SendMessage(UDS_RELAY_V3_PKT_PATH_RESPONSE, 0u,
                                s_relayV3Token, message->body,
                                message->body_length))
            return false;
        s_relayV3NextSendMs = nowMs;
        s_relayV3LastRxMs = nowMs;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_ROOM_LIST)
    {
        bool applied;
        RecursiveLock_Lock(&s_beaconLock);
        applied = udsRelayV3RoomsApply(&s_relayV3Rooms, message->body,
                                       message->body_length);
        RecursiveLock_Unlock(&s_beaconLock);
        if (!applied)
            return false;
        s_relayV3RoomListLastValidMs = nowMs;
        s_relayV3Confirmed = true;
        s_relayV3LastRxMs = nowMs;
        s_relayV3NextSendMs = nowMs + RELAY_V3_HEARTBEAT_MS;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_ROOM_CREATED)
    {
        bool accepted;
        RecursiveLock_Lock(&s_connLock);
        accepted = s_relayV3Role.kind == RELAY_V3_ROLE_HOST &&
                   s_relayV3Role.pending &&
                   !s_relayV3Role.retire_pending &&
                   relayV3Load64(message->body) == s_relayV3Role.epoch &&
                   memcmp(message->body + 8u, s_relayV3Role.room_id, 16u) == 0;
        if (accepted)
        {
            s_relayV3Role.pending = false;
            s_relayV3Role.active = true;
            s_relayV3Role.retry_attempt = 0;
            memset(&s_relayV3RetiringRole, 0,
                   sizeof(s_relayV3RetiringRole));
            memcpy(s_relayV3Scope, s_relayV3Role.scope,
                   sizeof(s_relayV3Scope));
            if (s_connStatus == UDS_STATUS_HOST)
            {
                s_connected = true;
                if (s_relayV3Role.peers.valid_mask != 0u)
                    relayV3PublishPeersLocked(
                        true, s_relayV3Role.peers.valid_mask);
            }
        }
        RecursiveLock_Unlock(&s_connLock);
        if (!accepted)
            return false;
        s_relayV3Confirmed = true;
        s_relayV3LastRxMs = nowMs;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_PEER_MAP &&
        relayV3ApplyPeerMap(message->body, message->body_length))
    {
        s_relayV3Confirmed = true;
        s_relayV3LastRxMs = nowMs;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_UDS_DATA &&
        (relayV3DlpAdvertReceive(message->header.flags, message->body,
                                 message->body_length) ||
         relayV3ReceiveJoinedData(message->header.flags, message->body,
                                  message->body_length)))
    {
        s_relayV3Confirmed = true;
        s_relayV3LastRxMs = nowMs;
        return true;
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_ERROR)
    {
        u32 code = relayV3Load32(message->body);
        u8 requestType = message->body[4];
        if (code == 1u && requestType == UDS_RELAY_V3_PKT_REGISTER &&
            memcmp(message->body + 8u, s_relayV3Token, 16u) == 0)
        {
            relayV3RetireLocal();
            (void)relayV3StartRegistration(nowMs);
            return true;
        }
        if (code == 8u && relayV3RetryIdConflict(message->body, nowMs))
        {
            s_relayV3Confirmed = true;
            s_relayV3LastRxMs = nowMs;
            return true;
        }
        bool retired = false;
        RecursiveLock_Lock(&s_connLock);
        if (s_relayV3RetiringRole.retire_pending &&
            requestType == s_relayV3RetiringRole.retire_type &&
            memcmp(message->body + 8u, s_relayV3RetiringRole.scope,
                   16u) == 0)
        {
            memset(&s_relayV3RetiringRole, 0,
                   sizeof(s_relayV3RetiringRole));
            retired = true;
        }
        RecursiveLock_Unlock(&s_connLock);
        if (retired)
        {
            s_relayV3Confirmed = true;
            s_relayV3LastRxMs = nowMs;
            return true;
        }
        bool terminal = false;
        RecursiveLock_Lock(&s_connLock);
        if (s_relayV3Role.pending &&
            requestType == s_relayV3Role.acquire_type &&
            memcmp(message->body + 8u, s_relayV3Role.scope, 16u) == 0)
            terminal = relayV3ScheduleRetireLocked(
                requestType == UDS_RELAY_V3_PKT_ROOM_CREATE
                    ? UDS_RELAY_V3_PKT_ROOM_CLOSE : UDS_RELAY_V3_PKT_LEAVE,
                0u, nowMs);
        RecursiveLock_Unlock(&s_connLock);
        if (terminal)
        {
            s_relayV3Confirmed = true;
            s_relayV3LastRxMs = nowMs;
            return true;
        }
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_DISCONNECT)
    {
        bool current;
        bool retiring;
        RecursiveLock_Lock(&s_connLock);
        current = s_relayV3Role.kind != RELAY_V3_ROLE_NONE &&
                  memcmp(message->body, s_relayV3Role.scope, 16u) == 0;
        retiring = !current && s_relayV3RetiringRole.retire_pending &&
                   memcmp(message->body, s_relayV3RetiringRole.scope,
                          16u) == 0;
        if (retiring)
            memset(&s_relayV3RetiringRole, 0,
                   sizeof(s_relayV3RetiringRole));
        RecursiveLock_Unlock(&s_connLock);
        if (current)
        {
            relayV3RetireLocal();
            (void)relayV3StartRegistration(nowMs);
            return true;
        }
        if (retiring)
        {
            s_relayV3Confirmed = true;
            s_relayV3LastRxMs = nowMs;
            return true;
        }
    }
    if (message->header.packet_type == UDS_RELAY_V3_PKT_RETIRE_ACK)
    {
        bool retiring;
        RecursiveLock_Lock(&s_connLock);
        retiring = s_relayV3RetiringRole.retire_pending &&
            message->body[0] == s_relayV3RetiringRole.retire_type &&
            relayV3Load64(message->body + 8u) ==
                s_relayV3RetiringRole.epoch &&
            memcmp(message->body + 16u, s_relayV3RetiringRole.scope,
                   16u) == 0;
        if (retiring)
            memset(&s_relayV3RetiringRole, 0,
                   sizeof(s_relayV3RetiringRole));
        RecursiveLock_Unlock(&s_connLock);
        if (retiring)
        {
            s_relayV3Confirmed = true;
            s_relayV3LastRxMs = nowMs;
            return true;
        }
    }
    return false;
}

static bool relayV3DriveRole(u64 nowMs, bool canSend)
{
    u8 packetType = 0;
    u8 body[0x148];
    u16 bodyLength = 0;
    u64 epoch = 0;
    u8 scope[16];
    bool resetConnection = false;
    bool prepareHost = false;
    bool sendingRetire = false;

    RecursiveLock_Lock(&s_connLock);
    bool expiredRetire = s_relayV3RetiringRole.retire_pending &&
        udsRelayV3DeadlineExpired(s_relayV3RetiringRole.started_ms, nowMs);
    bool expiredAcquire = s_relayV3Role.pending &&
        udsRelayV3DeadlineExpired(s_relayV3Role.started_ms, nowMs);
    if (expiredRetire)
    {
        if (s_relayV3Role.active)
            memset(&s_relayV3RetiringRole, 0,
                   sizeof(s_relayV3RetiringRole));
        else
            resetConnection = true;
    }
    else if (expiredAcquire)
    {
        (void)relayV3ScheduleRetireLocked(
            s_relayV3Role.kind == RELAY_V3_ROLE_HOST
                ? UDS_RELAY_V3_PKT_ROOM_CLOSE : UDS_RELAY_V3_PKT_LEAVE,
            0u, nowMs);
    }
    prepareHost = !resetConnection && canSend && s_relayV3Role.pending &&
                  nowMs >= s_relayV3Role.next_send_ms &&
                  s_relayV3Role.kind == RELAY_V3_ROLE_HOST &&
                  !s_relayV3Role.host_descriptor_prepared;
    RecursiveLock_Unlock(&s_connLock);

    if (resetConnection)
    {
        relayV3RetireLocal();
        return relayV3StartRegistration(nowMs);
    }
    if (prepareHost && !relayV3PrepareHostRole())
        return true;

    RecursiveLock_Lock(&s_connLock);
    RelayV3Role *outgoing = NULL;
    if (canSend && s_relayV3RetiringRole.retire_pending &&
        nowMs >= s_relayV3RetiringRole.next_send_ms)
    {
        outgoing = &s_relayV3RetiringRole;
        sendingRetire = true;
    }
    else if (canSend && s_relayV3Role.pending &&
             nowMs >= s_relayV3Role.next_send_ms &&
             (s_relayV3Role.kind != RELAY_V3_ROLE_HOST ||
              s_relayV3Role.host_descriptor_prepared))
        outgoing = &s_relayV3Role;
    if (outgoing != NULL)
    {
        epoch = outgoing->epoch;
        memcpy(scope, outgoing->scope, sizeof(scope));
        packetType = sendingRetire
            ? outgoing->retire_type : outgoing->acquire_type;
        if (sendingRetire)
        {
            bodyLength = 0x20u;
            memset(body, 0, bodyLength);
            relayV3Store64(body, epoch);
            memcpy(body + 8u, scope, sizeof(scope));
            body[24] = outgoing->retire_reason;
        }
        else
        {
            bodyLength = outgoing->acquire_body_length;
            memcpy(body, outgoing->acquire_body, bodyLength);
        }
    }
    RecursiveLock_Unlock(&s_connLock);
    if (packetType == 0u)
        return true;
    if (!relayV3SendMessage(packetType, 0u, s_relayV3Token,
                            body, bodyLength))
        return false;

    RecursiveLock_Lock(&s_connLock);
    outgoing = sendingRetire ? &s_relayV3RetiringRole : &s_relayV3Role;
    if (outgoing->epoch == epoch &&
        memcmp(outgoing->scope, scope, sizeof(scope)) == 0 &&
        ((sendingRetire && outgoing->retire_pending &&
          outgoing->retire_type == packetType) ||
         (!sendingRetire && outgoing->pending &&
          outgoing->acquire_type == packetType)))
    {
        outgoing->next_send_ms = nowMs +
            udsRelayV3RetryDelayMs(outgoing->retry_attempt);
        outgoing->retry_attempt++;
    }
    RecursiveLock_Unlock(&s_connLock);
    return true;
}

static bool relayV3DrainSend(void)
{
    while (true)
    {
        SendEntry entry;
        u8 scope[16];
        u16 src = 0;
        u32 sourceGeneration = 0;
        bool current = false;

        RecursiveLock_Lock(&s_connLock);
        if (s_sendRead == s_sendWrite)
        {
            RecursiveLock_Unlock(&s_connLock);
            return true;
        }
        entry = s_sendRing[s_sendRead % SEND_RING_CAP];
        if (s_relayV3Role.kind == RELAY_V3_ROLE_HOST &&
            s_relayV3Role.pending &&
            entry.sendGeneration == s_sendGeneration)
        {
            RecursiveLock_Unlock(&s_connLock);
            return true;
        }
        s_sendRead++;
        if (s_relayV3Role.active &&
            udsSendGenerationIsCurrent(
                entry.sendGeneration, s_sendGeneration, s_connStatus,
                s_connReason, s_ourNodeID, s_sessionId))
        {
            src = s_ourNodeID;
            sourceGeneration = s_relayV3Role.kind == RELAY_V3_ROLE_HOST
                ? 1u : s_relayV3Role.peers.node_generations[src - 1u];
            if (sourceGeneration != 0u)
            {
                memcpy(scope, s_relayV3Role.scope, sizeof(scope));
                current = true;
            }
        }
        RecursiveLock_Unlock(&s_connLock);
        if (!current)
            continue;

        memcpy(s_relayV3DataBody, scope, sizeof(scope));
        relayV3Store16(s_relayV3DataBody + 16u, src);
        relayV3Store16(s_relayV3DataBody + 18u, entry.dst);
        s_relayV3DataBody[20] = entry.channel;
        s_relayV3DataBody[21] = 0u;
        relayV3Store16(s_relayV3DataBody + 22u, entry.len);
        relayV3Store32(s_relayV3DataBody + 24u,
                       udsRelayV3Fnv1a32(entry.data, entry.len));
        relayV3Store32(s_relayV3DataBody + 28u, sourceGeneration);
        memcpy(s_relayV3DataBody + 32u, entry.data, entry.len);
        if (!relayV3SendMessage(
                UDS_RELAY_V3_PKT_UDS_DATA,
                entry.dst == UDS_NODE_BROADCAST
                    ? UDS_RELAY_V3_FLAG_BROADCAST
                    : UDS_RELAY_V3_FLAG_UNICAST,
                s_relayV3Token, s_relayV3DataBody,
                (u16)(32u + entry.len)))
            return false;
    }
}

static void relayV3ExpireRooms(u64 nowMs)
{
    RecursiveLock_Lock(&s_beaconLock);
    if (s_relayV3RoomListLastValidMs != 0u &&
        udsRelayV3DeadlineExpired(s_relayV3RoomListLastValidMs, nowMs))
    {
        udsRelayV3RoomsExpireVisibility(&s_relayV3Rooms);
        s_relayV3RoomListLastValidMs = 0u;
    }
    RecursiveLock_Unlock(&s_beaconLock);
}

static bool relayV3SocketOpen(const char *endpoint, u64 nowMs)
{
    Result result = miniSocInit();
    if (R_FAILED(result))
        return false;
    s_relayUp = true;
    u32 addrBE;
    u16 portBE;
    if (!UdsRedirect_ResolveBbpEndpoint(endpoint, &addrBE, &portBE))
    {
        relayV3SocketClose();
        return false;
    }
    s_relaySock = socSocket(AF_INET, SOCK_DGRAM, 0);
    if (s_relaySock < 0)
    {
        relayV3SocketClose();
        return false;
    }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = portBE;
    address.sin_addr.s_addr = addrBE;
    int connectResult = socConnect(s_relaySock, (struct sockaddr *)&address,
                                   sizeof(address));
    if (connectResult < 0)
    {
        relayV3SocketClose();
        return false;
    }
    udsRelayV3ReassemblerInit(&s_relayV3Reassembler);
    if (!relayV4StartHandshake())
    {
        relayV3SocketClose();
        return false;
    }
    s_relayV3StartedMs = udsRelayV3DeadlineStart(s_relayV3StartedMs, nowMs);
    s_relayV3RetryAttempt = 0;
    s_relayV3NextSendMs = nowMs + udsRelayV3RetryDelayMs(s_relayV3RetryAttempt++);
    return true;
}

static void relayV3StopForProxyOff(u64 nowMs)
{
    (void)nowMs;
    static const u8 empty[1] = {0};
    if (s_relaySock >= 0 && relayV3TokenReady())
        (void)relayV3SendMessage(UDS_RELAY_V3_PKT_UNREGISTER, 0u,
                                 s_relayV3Token, empty, 0u);
    relayV3SocketClose();
    relayV3RetireLocal();
    memset(s_relayV3Token, 0, sizeof(s_relayV3Token));
    memset(s_relayV3Nonce, 0, sizeof(s_relayV3Nonce));
    s_relayV3StartedMs = 0;
    s_relayV3LastRxMs = 0;
}

/* NAMESPACE stays latched until bbpConfigChangedLocked clears it. */
static bool relayV3StatusAllowsReconfigure(u32 status, bool configured)
{
    if (status == UDS_PROXY_CONFIG_OK)
        return true;
    if (status == UDS_PROXY_CONFIG_NAMESPACE)
        return false;
    return !configured;
}

static void relayV3ThreadMain(void)
{
    bool configured = false;
    u32 configGeneration = 0;
    beaconLockInitOnce();
    RecursiveLock_Lock(&s_beaconLock);
    memset(&s_relayV3Rooms, 0, sizeof(s_relayV3Rooms));
    s_relayV3RoomListLastValidMs = 0;
    RecursiveLock_Unlock(&s_beaconLock);
    memset(s_relayV3Token, 0, sizeof(s_relayV3Token));

    while (!preTerminationRequested)
    {
        u64 nowMs = relayV3NowMs();
        RecursiveLock_Lock(&s_connLock);
        s_bbpHealthGeneration = configGeneration;
        s_bbpConfirmed = s_relayV3Confirmed;
        s_bbpSocketOpen = s_relaySock >= 0;
        s_bbpLastRxMs = s_relayV3LastRxMs;
        s_bbpStartedMs = s_relayV3StartedMs;
        RecursiveLock_Unlock(&s_connLock);
        UdsBbpSnapshot config;
        UdsRedirect_GetBbpSnapshot(&config);
        u32 generation = config.generation;
        if (generation != configGeneration)
        {
            if (configured || s_relaySock >= 0 || relayV3TokenReady())
                relayV3StopForProxyOff(nowMs);
            configured = false;
            configGeneration = generation;
        }
        if (!config.enabled)
        {
            if (configured || s_relaySock >= 0 || relayV3TokenReady())
                relayV3StopForProxyOff(nowMs);
            configured = false;
            svcSleepThread(1000 * 1000 * 1000LL);
            continue;
        }
        if (!relayV3StatusAllowsReconfigure(config.configStatus, configured))
        {
            relayV3StopForProxyOff(nowMs);
            configured = false;
            svcSleepThread(1000 * 1000 * 1000LL);
            continue;
        }
        if (!configured)
        {
            u8 address[4];
            u16 port;
            if (!config.valid[config.selected] ||
                (config.selected == 0
                    ? strcmp(config.endpoints[0], BBP_OFFICIAL_ENDPOINT) != 0
                    : !udsRelayV3HostParse(config.endpoints[config.selected],
                        strlen(config.endpoints[config.selected]), address, &port)))
            {
                bbpSetConfigStatus(UDS_PROXY_CONFIG_RELAY_HOST);
                svcSleepThread(1000 * 1000 * 1000LL);
                continue;
            }
            s_relayV3Channel = config.channel;
            s_relayV3Pin = config.pin;
            s_relayV3ConfigGeneration = generation;
            if (!relayV3ReadOrCreateClientId())
            {
                bbpSetConfigStatus(UDS_PROXY_CONFIG_CLIENT_ID);
                svcSleepThread(1000 * 1000 * 1000LL);
                continue;
            }
            RecursiveLock_Lock(&s_beaconLock);
            memset(&s_relayV3Rooms, 0, sizeof(s_relayV3Rooms));
            s_relayV3RoomListLastValidMs = 0;
            RecursiveLock_Unlock(&s_beaconLock);
            memset(s_relayV3Token, 0, sizeof(s_relayV3Token));
            configured = true;
            bbpSetConfigStatus(UDS_PROXY_CONFIG_OK);
        }
        relayReclaimFreedBinds();
        relayV3ExpireRooms(nowMs);
        if (relayV3BbpExited(nowMs))
        {
            bool scheduled = false;
            RecursiveLock_Lock(&s_connLock);
            if (s_relayV3Role.kind == RELAY_V3_ROLE_HOST)
                scheduled = relayV3ScheduleRetireLocked(
                    UDS_RELAY_V3_PKT_ROOM_CLOSE, 0u, nowMs);
            else if (s_relayV3Role.kind == RELAY_V3_ROLE_GUEST)
                scheduled = relayV3ScheduleRetireLocked(
                    UDS_RELAY_V3_PKT_LEAVE, 0u, nowMs);
            RecursiveLock_Unlock(&s_connLock);
            if (!scheduled)
            {
                relayV3RetireLocal();
                (void)relayV3StartRegistration(nowMs);
            }
        }
        if (!relayV3DriveRole(nowMs, false))
        {
            relayV3SocketClose();
            svcSleepThread(1000 * 1000 * 1000LL);
            continue;
        }
        bool roleOwnsDeadline;
        RecursiveLock_Lock(&s_connLock);
        roleOwnsDeadline = s_relayV3Role.pending ||
                           s_relayV3RetiringRole.retire_pending;
        RecursiveLock_Unlock(&s_connLock);
        if (relayV3TokenReady() && !roleOwnsDeadline &&
            ((!s_relayV3Confirmed &&
              udsRelayV3DeadlineExpired(s_relayV3StartedMs, nowMs)) ||
             (s_relayV3Confirmed &&
              udsRelayV3DeadlineExpired(s_relayV3LastRxMs, nowMs))))
        {
            relayV3RetireLocal();
            bool registrationStarted = relayV3StartRegistration(nowMs);
            bool handshakeStarted = registrationStarted && relayV4StartHandshake();
            if (!registrationStarted || !handshakeStarted)
            {
                relayV3SocketClose();
                svcSleepThread(1000 * 1000 * 1000LL);
                continue;
            }
            s_relayV3RetryAttempt = 0u;
            s_relayV3NextSendMs = nowMs +
                udsRelayV3RetryDelayMs(s_relayV3RetryAttempt++);
        }
        if (s_relaySock < 0)
        {
            bool socRegistered = false;
            Result gateResult = srvIsServiceRegistered(&socRegistered, "soc:U");
            if (R_FAILED(gateResult) || !socRegistered || !Wifi__IsConnected())
            {
                relayV3SocketClose();
                __dmb();
                svcSleepThread(1000 * 1000 * 1000LL);
                continue;
            }
        }

        nowMs = relayV3NowMs();
        if (s_relaySock < 0)
        {
            if (!relayV3SocketOpen(config.endpoints[config.selected], nowMs))
            {
                svcSleepThread(1000 * 1000 * 1000LL);
                continue;
            }
            if (!relayV3TokenReady() && !relayV3StartRegistration(nowMs))
            {
                relayV3SocketClose();
                svcSleepThread(1000 * 1000 * 1000LL);
                continue;
            }
        }

        for (u32 drain = 0; drain < 32u; drain++)
        {
            struct pollfd poll = { .fd = s_relaySock, .events = POLLIN,
                                   .revents = 0 };
            int pollResult = socPoll(&poll, 1, 0);
            if (pollResult < 0)
            {
                relayV3SocketClose();
                break;
            }
            if (pollResult == 0 || !(poll.revents & POLLIN))
                break;
            int received = socRecv(s_relaySock, s_relayRx,
                                   UDS_RELAY_V4_MAX_DATAGRAM, 0);
            if (received <= 0)
            {
                if (received < 0)
                    relayV3SocketClose();
                break;
            }
            nowMs = relayV3NowMs();
            if (!udsRelayV4ClientReady(&s_relayV4Client))
            {
                size_t responseLength = 0u;
                if (udsRelayV4ClientHandshake(
                        &s_relayV4Client, s_relayRx, (size_t)received,
                        s_relayV4Tx, sizeof(s_relayV4Tx), &responseLength))
                {
                    if (responseLength != 0u)
                    {
                        int sendResult = socSend(s_relaySock, s_relayV4Tx,
                                                 responseLength, 0);
                        if (sendResult != (int)responseLength)
                        {
                            relayV3SocketClose();
                            break;
                        }
                    }
                    if (udsRelayV4ClientReady(&s_relayV4Client))
                    {
                        s_relayV3RetryAttempt = 0u;
                        s_relayV3NextSendMs = nowMs;
                    }
                }
                continue;
            }
            size_t plaintextLength = 0u;
            if (!udsRelayV4ClientDecrypt(
                    &s_relayV4Client, s_relayRx, (size_t)received,
                    s_relayV4Plain, sizeof(s_relayV4Plain), &plaintextLength) ||
                plaintextLength < 8u)
                continue;
            if (udsRelayV3ReassemblerPush(&s_relayV3Reassembler, s_relayV4Plain,
                                           plaintextLength, nowMs, &s_relayV3Message))
                (void)relayV3HandleMessage(nowMs);
        }
        if (s_relaySock < 0 || s_proxyConfigStatus != UDS_PROXY_CONFIG_OK)
            continue;

        nowMs = relayV3NowMs();
        if (!udsRelayV4ClientReady(&s_relayV4Client))
        {
            if (nowMs >= s_relayV3NextSendMs)
            {
                if (!relayV4SendHello())
                {
                    relayV3SocketClose();
                    continue;
                }
                s_relayV3NextSendMs = nowMs +
                    udsRelayV3RetryDelayMs(s_relayV3RetryAttempt++);
            }
            svcSleepThread(20 * 1000 * 1000LL);
            continue;
        }
        if (!relayV3DriveRole(nowMs, s_relayV3Confirmed &&
                              relayV3TokenReady()))
        {
            relayV3SocketClose();
            continue;
        }
        if (s_relayV3Confirmed && !relayV3DrainSend())
        {
            relayV3SocketClose();
            continue;
        }
        if (nowMs >= s_relayV3NextSendMs)
        {
            bool heartbeat = relayV3TokenReady();
            bool sent = heartbeat
                ? relayV3SendHeartbeat() : relayV3SendRegister();
            if (!sent)
            {
                relayV3SocketClose();
                continue;
            }
            s_relayV3NextSendMs = nowMs + (s_relayV3Confirmed
                ? RELAY_V3_HEARTBEAT_MS
                : udsRelayV3RetryDelayMs(s_relayV3RetryAttempt++));
        }
        svcSleepThread(20 * 1000 * 1000LL);
    }
    relayV3StopForProxyOff(relayV3NowMs());
    if (s_relayV3BbpProcess != 0)
    {
        svcCloseHandle(s_relayV3BbpProcess);
        s_relayV3BbpProcess = 0;
    }
}

static bool relayV3BuildScan(u32 wlanCommId, u8 id8, u8 *output,
                             u32 outputCapacity, u8 *outCount)
{
    bool built;
    RecursiveLock_Lock(&s_beaconLock);
    built = udsRelayV3RoomsBuildScan(&s_relayV3Rooms, wlanCommId, id8,
                                     output, outputCapacity, outCount);
    RecursiveLock_Unlock(&s_beaconLock);
    return built;
}

void UdsRedirect_CreateRelayThread(void)
{
    connLockInitOnce();
    psLockInitOnce();
    Result r = MyThread_Create(&s_relayThread, relayV3ThreadMain, s_relayThreadStack,
                               sizeof(s_relayThreadStack), 0x20, CORE_SYSTEM);
    (void)r;
}

/* Static buffers: 0=passphrase/PullPacket, 1=network info, 2/3=beacon tags,
 * 4=application data, 5=SendTo payload. */
static u8 s_sb0[0x1000] __attribute__((aligned(4)));
static u8 s_sb1[0x200]  __attribute__((aligned(4)));
static u8 s_sb2[0x100]  __attribute__((aligned(4)));
static u8 s_sb3[0x100]  __attribute__((aligned(4)));
static u8 s_sb4[0x100]  __attribute__((aligned(4)));
static u8 s_sb5[0x1000] __attribute__((aligned(4)));

static void setupStaticBuffers(void)
{
    u32 *sb = getThreadStaticBuffers();
    memset(sb, 0, 16 * sizeof(u32));
    sb[0]  = IPC_Desc_StaticBuffer(sizeof(s_sb0), 0); sb[1]  = (u32)s_sb0;
    sb[2]  = IPC_Desc_StaticBuffer(sizeof(s_sb1), 1); sb[3]  = (u32)s_sb1;
    sb[4]  = IPC_Desc_StaticBuffer(sizeof(s_sb2), 2); sb[5]  = (u32)s_sb2;
    sb[6]  = IPC_Desc_StaticBuffer(sizeof(s_sb3), 3); sb[7]  = (u32)s_sb3;
    sb[8]  = IPC_Desc_StaticBuffer(sizeof(s_sb4), 4); sb[9]  = (u32)s_sb4;
    sb[10] = IPC_Desc_StaticBuffer(sizeof(s_sb5), 5); sb[11] = (u32)s_sb5;
}

static Handle s_sharedmem = 0; // owned until Finalize
static u8     s_ownNodeInfo[0x28];
static bool   s_haveOwnNodeInfo = false;

#define UDS_OUT_OF_RESOURCE 0xC8A10000u

static void publishSelectedVisibleLocked(u8 role)
{
    bool nextSpectator = role == UDS_CONNECT_ROLE_SPECTATOR;
    if (!nextSpectator)
        dlpAdvertCacheClearLocked();
    s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
    s_joinAttemptSerial++;
    s_isSpectator = nextSpectator;
    if (s_isSpectator)
    {
        s_connected = true;
        s_wantJoin = false;
        s_joinInFlight = false;
        s_connStatus = UDS_STATUS_SPECTATOR;
        s_connReason = UDS_REASON_ESTABLISHED;
        s_ourNodeID = 0;
        s_sessionId = 0;
        s_connNodeMask = 0x1u;
        s_connChanged = 0x1u;
        if (s_connEvent) svcSignalEvent(s_connEvent);
    }
    else
    {
        s_connected = true;
        s_wantJoin = true;
        s_joinInFlight = false;
        s_connStatus = UDS_STATUS_CONNECTING;
        s_connReason = UDS_REASON_NONE;
        s_ourNodeID = 0;
        s_sessionId = 0;
        s_connNodeMask = 0;
        s_connChanged = 0;
    }
}

/* Return a moved duplicate; retain the original for relay-thread signaling. */
static Result hleMakeEvent(Handle *keep, u32 *outClientHandle)
{
    if (*keep == 0)
    {
        Result r = svcCreateEvent(keep, RESET_ONESHOT);
        if (R_FAILED(r)) { *keep = 0; return r; }
    }
    Handle dup = 0;
    Result r = svcDuplicateHandle(&dup, *keep);
    if (R_FAILED(r)) return r;
    *outClientHandle = (u32)dup;
    return 0;
}

static void hleCleanupFinalizeState(void)
{
    /* Signal before closing so waiters holding duplicated handles are released. */
    RecursiveLock_Lock(&s_connLock);
    if (s_connEvent) { svcSignalEvent(s_connEvent); svcCloseHandle(s_connEvent); s_connEvent = 0; }
    s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
    s_joinAttemptSerial++;
    s_wantJoin = false;
    s_joinInFlight = false;
    s_sendWrite = 0;
    s_sendRead = 0;
    s_connected = false;
    s_isSpectator = false;
    s_maxNodes = 1;
    connResetVisibleLocked();
    RecursiveLock_Lock(&s_beaconLock);
    memset(s_relayV3Rooms.latches, 0, sizeof(s_relayV3Rooms.latches));
    dlpAdvertCacheClearLocked();
    RecursiveLock_Unlock(&s_beaconLock);
    for (u32 i = 0; i < MAX_BINDS; i++)
    {
        s_binds[i].used = false;
        if (s_binds[i].event) { svcCloseHandle(s_binds[i].event); s_binds[i].event = 0; }
    }
    memset(s_binds, 0, sizeof(s_binds));
    RecursiveLock_Unlock(&s_connLock);

    if (s_sharedmem) { svcCloseHandle(s_sharedmem); s_sharedmem = 0; }

    s_haveOwnNodeInfo = false;

    memset(s_ownNodeInfo, 0, sizeof(s_ownNodeInfo));
}

static bool relayV3SendToValuesValid(u16 dst, u8 channel)
{
    return (dst == UDS_NODE_BROADCAST || (dst >= 1u && dst <= 16u)) &&
           channel != 0u;
}

static void hleHandle(u32 *cmdbuf, u32 cmdId)
{
    switch (cmdId)
    {
    case 0x05: // EjectClient (success no-op)
    case 0x07: // UpdateNetworkAttribute (success no-op)
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, 0);
        cmdbuf[1] = 0;
        return;
    case 0x1A: // GetChannel (virtual Wi-Fi, not matchmaking)
    {
        u8 channel = 0;
        RecursiveLock_Lock(&s_connLock);
        if (s_connStatus != UDS_STATUS_DISCONNECTED)
        {
            if (s_relayV3Role.kind == RELAY_V3_ROLE_HOST)
                channel = s_relayV3Role.host_raw_network_info[6];
            else if (s_relayV3SelectedRoom.valid)
                channel = s_relayV3SelectedRoom.network_info[6];
            // Descriptor channel 0 requests automatic selection.
            if (channel == 0) channel = 11;
        }
        RecursiveLock_Unlock(&s_connLock);
        cmdbuf[0] = IPC_MakeHeader(0x1A, 2, 0);
        cmdbuf[1] = 0;
        cmdbuf[2] = channel;
        return;
    }
    case 0x08: // DestroyNetwork
    {
        RecursiveLock_Lock(&s_connLock);
        if (!relayV3ScheduleRetireLocked(UDS_RELAY_V3_PKT_ROOM_CLOSE,
                                         0u, relayV3NowMs()))
        {
            s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
            s_connected = false;
            connResetVisibleLocked();
            if (s_connEvent) svcSignalEvent(s_connEvent);
        }
        cmdbuf[0] = IPC_MakeHeader(0x08, 1, 0);
        cmdbuf[1] = 0;
        RecursiveLock_Unlock(&s_connLock);
        return;
    }
    case 0x0A: // DisconnectNetwork
    {
        RecursiveLock_Lock(&s_connLock);
        bool establishedGuest = s_relayV3Role.kind == RELAY_V3_ROLE_GUEST &&
                                s_relayV3Role.active;
        if (!establishedGuest ||
            !relayV3ScheduleRetireLocked(UDS_RELAY_V3_PKT_LEAVE,
                                          0u, relayV3NowMs()))
        {
            s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
            s_connected = false;
            s_isSpectator = false;
            connResetVisibleLocked();
            if (s_connEvent) svcSignalEvent(s_connEvent);
        }
        cmdbuf[0] = IPC_MakeHeader(0x0A, 1, 0);
        cmdbuf[1] = 0;
        RecursiveLock_Unlock(&s_connLock);
        return;
    }
    case 0x1B: // InitializeWithVersion
    {
        /* Request: size@1, NodeInfo@2..0xb, version@0xc. */
        memcpy(s_ownNodeInfo, &cmdbuf[2], sizeof(s_ownNodeInfo));
        s_haveOwnNodeInfo = true;
        Handle sm = (Handle)cmdbuf[14]; // copied handle, owned by this service
        if (s_sharedmem == 0) s_sharedmem = sm;
        else if (sm != 0)     svcCloseHandle(sm);
        u32 ev = 0;
        RecursiveLock_Lock(&s_connLock);
        Result r = hleMakeEvent(&s_connEvent, &ev);
        RecursiveLock_Unlock(&s_connLock);
        if (R_FAILED(r)) { cmdbuf[0] = IPC_MakeHeader(0x1B, 1, 0); cmdbuf[1] = (u32)r; return; }
        cmdbuf[0] = IPC_MakeHeader(0x1B, 1, 2);
        cmdbuf[1] = 0;
        cmdbuf[2] = IPC_Desc_MoveHandles(1);
        cmdbuf[3] = ev;
        return;
    }
    case 0x1D: // BeginHostingNetwork / CreateNetwork2
    {
        /* Static buffer 1: big-endian network info; max_nodes is one byte at 0x1D. */
        u8 requestedMaxNodes = s_sb1[0x1D];
        bool validMaxNodes = requestedMaxNodes >= 2u && requestedMaxNodes <= 16u;
        if (!validMaxNodes)
        {
            cmdbuf[0] = IPC_MakeHeader(0x1D, 1, 0);
            cmdbuf[1] = UDS_OUT_OF_RESOURCE;
            return;
        }

        u8 roomId[16];
        bool same;
        bool idle;
        RecursiveLock_Lock(&s_connLock);
        same = s_relayV3Role.kind == RELAY_V3_ROLE_HOST &&
               !s_relayV3Role.retire_pending &&
               s_relayV3Role.acquire_body_length == 0x148u &&
               memcmp(s_relayV3Role.host_raw_network_info, s_sb1,
                      UDS_RELAY_V3_NETWORK_INFO_SIZE) == 0 &&
               memcmp(s_relayV3Role.host_raw_node_info, s_ownNodeInfo,
                      UDS_RELAY_V3_NODE_INFO_SIZE) == 0;
        idle = s_relayV3Role.kind == RELAY_V3_ROLE_NONE;
        RecursiveLock_Unlock(&s_connLock);
        if (!same && (!idle || !s_haveOwnNodeInfo ||
                      !relayV3GenerateUuid(roomId)))
        {
            cmdbuf[0] = IPC_MakeHeader(0x1D, 1, 0);
            cmdbuf[1] = UDS_OUT_OF_RESOURCE;
            return;
        }

        RecursiveLock_Lock(&s_connLock);
        if (!same)
        {
            if (s_relayV3Role.kind != RELAY_V3_ROLE_NONE ||
                s_relayV3RoleCounter == UINT64_MAX)
            {
                RecursiveLock_Unlock(&s_connLock);
                cmdbuf[0] = IPC_MakeHeader(0x1D, 1, 0);
                cmdbuf[1] = UDS_OUT_OF_RESOURCE;
                return;
            }
            s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
            memset(&s_relayV3Role, 0, sizeof(s_relayV3Role));
            s_relayV3Role.epoch = ++s_relayV3RoleCounter;
            s_relayV3Role.kind = RELAY_V3_ROLE_HOST;
            s_relayV3Role.max_nodes = requestedMaxNodes;
            s_relayV3Role.acquire_type = UDS_RELAY_V3_PKT_ROOM_CREATE;
            s_relayV3Role.acquire_body_length = 0x148u;
            s_relayV3Role.pending = true;
            s_relayV3Role.started_ms = relayV3NowMs();
            s_relayV3Role.next_send_ms = s_relayV3Role.started_ms;
            memcpy(s_relayV3Role.room_id, roomId, sizeof(roomId));
            memcpy(s_relayV3Role.scope, roomId, sizeof(roomId));
            relayV3Store64(s_relayV3Role.acquire_body,
                           s_relayV3Role.epoch);
            memcpy(s_relayV3Role.acquire_body + 8u, roomId,
                   sizeof(roomId));
            memcpy(s_relayV3Role.acquire_body + 0x18u, s_sb1,
                   UDS_RELAY_V3_NETWORK_INFO_SIZE);
            memcpy(s_relayV3Role.host_raw_network_info, s_sb1,
                   UDS_RELAY_V3_NETWORK_INFO_SIZE);
            memcpy(s_relayV3Role.host_raw_node_info, s_ownNodeInfo,
                   UDS_RELAY_V3_NODE_INFO_SIZE);
            memcpy(s_relayV3Role.own_node_info,
                   s_relayV3Role.host_raw_node_info,
                   UDS_RELAY_V3_NODE_INFO_SIZE);
            memcpy(s_relayV3Role.acquire_body + 0x120u,
                   s_relayV3Role.host_raw_node_info,
                   UDS_RELAY_V3_NODE_INFO_SIZE);
            relayV3Store16(s_relayV3Role.acquire_body + 0x120u + 0x20u,
                           1u);
        }
        s_maxNodes = requestedMaxNodes;
        s_hosting = true;
        s_connected = s_relayV3Role.active;
        s_isSpectator = false;
        s_ourNodeID = 1u;
        s_sessionId = 0u;
        s_connStatus = UDS_STATUS_HOST;
        s_connReason = UDS_REASON_ESTABLISHED;
        s_connNodeMask = 0x1u;
        s_connChanged |= 0x1u;
        if (s_connEvent) svcSignalEvent(s_connEvent);
        RecursiveLock_Unlock(&s_connLock);
        cmdbuf[0] = IPC_MakeHeader(0x1D, 1, 0);
        cmdbuf[1] = 0;
        return;
    }
    case 0x1E: // ConnectToNetwork
    {
        u8 connType = (u8)cmdbuf[1];
        u8 role = udsConnectTypeRole(connType);
        u8 maxNodes = s_sb1[0x1D];
        bool validMaxNodes = maxNodes >= 2u && maxNodes <= 16u;
        u8 membershipId[16];
        bool uuidReady = false;
        bool selected;
        bool fresh;
        bool sameGuest;
        bool idle;
        RecursiveLock_Lock(&s_connLock);
        RecursiveLock_Lock(&s_beaconLock);
        selected = validMaxNodes &&
                   (role == UDS_CONNECT_ROLE_CLIENT ||
                    role == UDS_CONNECT_ROLE_SPECTATOR) &&
                   s_relayV3SelectedRoom.valid &&
                   s_relayV3SelectedRole == role &&
                   udsBeaconCandidateMatchesCmd1E(
                       s_sb1, UDS_RELAY_V3_NETWORK_INFO_SIZE,
                       &s_relayV3SelectedRoom.identity);
        fresh = !selected && validMaxNodes &&
                (role == UDS_CONNECT_ROLE_CLIENT ||
                 role == UDS_CONNECT_ROLE_SPECTATOR) &&
                udsRelayV3RoomsFindLatchedNetwork(
                    &s_relayV3Rooms, s_sb1) >= 0;
        sameGuest = selected && role == UDS_CONNECT_ROLE_CLIENT &&
                    s_relayV3Role.kind == RELAY_V3_ROLE_GUEST &&
                    !s_relayV3Role.retire_pending &&
                    memcmp(s_relayV3Role.room_id,
                           s_relayV3SelectedRoom.room_id, 16u) == 0;
        idle = s_relayV3Role.kind == RELAY_V3_ROLE_NONE;
        RecursiveLock_Unlock(&s_beaconLock);
        RecursiveLock_Unlock(&s_connLock);
        if ((!selected && !fresh) ||
            (role == UDS_CONNECT_ROLE_SPECTATOR && !idle) ||
            (role == UDS_CONNECT_ROLE_CLIENT && !sameGuest &&
             (!idle || !s_haveOwnNodeInfo ||
              !(uuidReady = relayV3GenerateUuid(membershipId)))))
        {
            cmdbuf[0] = IPC_MakeHeader(0x1E, 1, 0);
            cmdbuf[1] = UDS_OUT_OF_RESOURCE;
            return;
        }

        RecursiveLock_Lock(&s_connLock);
        RecursiveLock_Lock(&s_beaconLock);
        selected = validMaxNodes &&
                   s_relayV3SelectedRoom.valid &&
                   s_relayV3SelectedRole == role &&
                   udsBeaconCandidateMatchesCmd1E(
                       s_sb1, UDS_RELAY_V3_NETWORK_INFO_SIZE,
                       &s_relayV3SelectedRoom.identity);
        int roomIndex = selected ? -1 :
            udsRelayV3RoomsFindLatchedNetwork(&s_relayV3Rooms, s_sb1);
        sameGuest = selected && role == UDS_CONNECT_ROLE_CLIENT &&
                    s_relayV3Role.kind == RELAY_V3_ROLE_GUEST &&
                    !s_relayV3Role.retire_pending &&
                    memcmp(s_relayV3Role.room_id,
                           s_relayV3SelectedRoom.room_id, 16u) == 0;
        idle = s_relayV3Role.kind == RELAY_V3_ROLE_NONE;
        selected = (selected || roomIndex >= 0) &&
            ((role == UDS_CONNECT_ROLE_SPECTATOR && idle) ||
             (role == UDS_CONNECT_ROLE_CLIENT &&
              (sameGuest || (idle && uuidReady && s_haveOwnNodeInfo &&
                             s_relayV3RoleCounter != UINT64_MAX))));
        if (selected && roomIndex >= 0)
        {
            roomIndex = udsRelayV3RoomsTakeLatchedNetwork(
                &s_relayV3Rooms, s_sb1);
            selected = roomIndex >= 0;
            if (selected)
            {
                UdsRelayV3Room *room = &s_relayV3Rooms.slots[roomIndex];
                if (!s_relayV3SelectedRoom.valid ||
                    s_relayV3SelectedRoom.generation != room->generation ||
                    memcmp(s_relayV3SelectedRoom.room_id,
                           room->room_id, 16u) != 0)
                    relayV3DlpAdvertSelectionChangedLocked();
                memcpy(&s_relayV3SelectedRoom, room,
                       sizeof(s_relayV3SelectedRoom));
                s_relayV3SelectedRole = role;
            }
        }
        if (selected && role == UDS_CONNECT_ROLE_CLIENT && !sameGuest)
        {
            memset(&s_relayV3Role, 0, sizeof(s_relayV3Role));
            s_relayV3Role.epoch = ++s_relayV3RoleCounter;
            s_relayV3Role.kind = RELAY_V3_ROLE_GUEST;
            s_relayV3Role.max_nodes = maxNodes;
            s_relayV3Role.acquire_type = UDS_RELAY_V3_PKT_JOIN;
            s_relayV3Role.acquire_body_length = 0x50u;
            s_relayV3Role.pending = true;
            s_relayV3Role.started_ms = relayV3NowMs();
            s_relayV3Role.next_send_ms = s_relayV3Role.started_ms;
            memcpy(s_relayV3Role.room_id,
                   s_relayV3SelectedRoom.room_id, 16u);
            memcpy(s_relayV3Role.scope, membershipId,
                   sizeof(membershipId));
            relayV3Store64(s_relayV3Role.acquire_body,
                           s_relayV3Role.epoch);
            memcpy(s_relayV3Role.acquire_body + 8u,
                   s_relayV3SelectedRoom.room_id, 16u);
            memcpy(s_relayV3Role.acquire_body + 24u, membershipId,
                   sizeof(membershipId));
            memcpy(s_relayV3Role.acquire_body + 40u, s_ownNodeInfo,
                   UDS_RELAY_V3_NODE_INFO_SIZE);
            memcpy(s_relayV3Role.own_node_info, s_ownNodeInfo,
                   UDS_RELAY_V3_NODE_INFO_SIZE);
            sameGuest = true;
        }
        if (selected)
            s_maxNodes = maxNodes;
        if (selected && role == UDS_CONNECT_ROLE_CLIENT &&
            s_relayV3Role.active)
        {
            dlpAdvertCacheClearLocked();
            s_sendGeneration = udsSendGenerationNext(s_sendGeneration);
            s_isSpectator = false;
            s_hosting = false;
            s_connected = true;
            s_wantJoin = false;
            s_joinInFlight = false;
            s_ourNodeID = s_relayV3Role.peers.local_node;
            s_sessionId = RELAY_NATIVE_SESSION_ID;
            s_connStatus = UDS_STATUS_CLIENT;
            s_connReason = UDS_REASON_ESTABLISHED;
            s_connNodeMask = s_relayV3Role.peers.valid_mask;
            s_connChanged |= s_connNodeMask;
            if (s_connEvent) svcSignalEvent(s_connEvent);
        }
        else if (selected)
        {
            publishSelectedVisibleLocked(role);
        }
        RecursiveLock_Unlock(&s_beaconLock);
        RecursiveLock_Unlock(&s_connLock);
        cmdbuf[0] = IPC_MakeHeader(0x1E, 1, 0);
        cmdbuf[1] = selected ? 0u : UDS_OUT_OF_RESOURCE;
        return;
    }
    case 0x12: // Bind
    {
        // Request: [1]=BindNodeID [2]=recv_buffer_size [3]=data_channel [4]=NetworkNodeID.
        u32 bindNodeID = cmdbuf[1];
        u32 recvBufferSize = cmdbuf[2];
        u32 recvCapacitySlots;
        u8  channel    = (u8)cmdbuf[3];
        u16 srcFilter  = (u16)cmdbuf[4];
        if (recvBufferSize > UDS_RECV_RING_MAX_SLOTS * UDS_RECV_RING_SLOT_SIZE)
        {
            cmdbuf[0] = IPC_MakeHeader(0x12, 1, 0);
            cmdbuf[1] = 0xC8A10000;
            return;
        }
        recvCapacitySlots = recvBufferSize >> 5;
        if (recvCapacitySlots < 2u || recvCapacitySlots > UDS_RECV_RING_MAX_SLOTS)
        {
            cmdbuf[0] = IPC_MakeHeader(0x12, 1, 0);
            cmdbuf[1] = 0xC8A10000;
            return;
        }
        bool advertSeedReady = channel == DLP_ADVERT_CHANNEL &&
                               relayV3DlpAdvertEnsureSeed();
        RecursiveLock_Lock(&s_connLock);
        BindSlot *b = bindByChannel(channel);
        if (b != NULL)
        {
            b->used = false;
            /* Retain the event handle across rebinds. */
        }
        if (b == NULL)
            for (u32 i = 0; i < MAX_BINDS; i++)
                if (!s_binds[i].used) { b = &s_binds[i]; break; }
        if (b == NULL)
        {
            RecursiveLock_Unlock(&s_connLock);
            cmdbuf[0] = IPC_MakeHeader(0x12, 1, 0);
            cmdbuf[1] = 0xC8A10000;
            return;
        }
        u32 ev = 0;
        Result r = hleMakeEvent(&b->event, &ev);
        if (R_FAILED(r))
        {
            RecursiveLock_Unlock(&s_connLock);
            cmdbuf[0] = IPC_MakeHeader(0x12, 1, 0);
            cmdbuf[1] = (u32)r;
            return;
        }
        if (!udsRecvRingV3Init(&b->ring,
                             recvCapacitySlots * UDS_RECV_RING_SLOT_SIZE))
        {
            RecursiveLock_Unlock(&s_connLock);
            cmdbuf[0] = IPC_MakeHeader(0x12, 1, 0);
            cmdbuf[1] = 0xC8A10000;
            return;
        }
        b->bindNodeID = bindNodeID;
        b->channel = channel;
        b->srcNodeFilter = srcFilter;
        b->used = true;
        b->freedTick = 0;
        {
            bool primed = false;
            Handle primeEvent = 0;
            RecursiveLock_Lock(&s_beaconLock);
            if (channel == DLP_ADVERT_CHANNEL)
            {
                s_dlpAdvertPrimed = false;
                if (advertSeedReady && relayV3DlpAdvertSeedMatchesLocked())
                    udsDlpAdvertCacheValidate(&s_dlpAdvertCache,
                                              s_dlpAdvertSeedValue);
            }
            primed = relayV3DlpAdvertPrimeBindLocked(b);
            if (primed) primeEvent = b->event;
            RecursiveLock_Unlock(&s_beaconLock);
            if (primed && primeEvent != 0) svcSignalEvent(primeEvent);
        }
        RecursiveLock_Unlock(&s_connLock);
        cmdbuf[0] = IPC_MakeHeader(0x12, 1, 2);
        cmdbuf[1] = 0;
        cmdbuf[2] = IPC_Desc_MoveHandles(1);
        cmdbuf[3] = ev;
        return;
    }
    case 0x0B: // GetConnectionStatus
               // Layout: status@0, reason@4, own@8, changed@A, nodes[16]@C,
               // total@2C, max@2D, node mask@2E (0x30 bytes).
    {
        u8 st[0x30];
        memset(st, 0, sizeof(st));
        u32 status, reason;
        u16 ownNode, changed, mask;
        u8 maxNodes;

        RecursiveLock_Lock(&s_connLock);
        status = s_connStatus;
        reason = s_connReason;
        ownNode = status == UDS_STATUS_SPECTATOR ? 0u : s_ourNodeID;
        changed = s_connChanged;
        mask = s_connNodeMask;
        maxNodes = s_maxNodes;
        s_connChanged = 0;
        RecursiveLock_Unlock(&s_connLock);

        *(u32 *)(st + 0x00) = status;
        *(u32 *)(st + 0x04) = reason;
        *(u16 *)(st + 0x08) = ownNode;
        *(u16 *)(st + 0x0A) = changed;
        u8 total = 0;
        for (u16 node = 1; node <= 16u; node++)
        {
            if ((mask & (u16)(1u << (node - 1))) != 0)
            {
                *(u16 *)(st + 0x0C + (node - 1u) * 2u) = node;
                total++;
            }
        }
        st[0x2C] = total;
        st[0x2D] = maxNodes;
        *(u16 *)(st + 0x2E) = mask;
        cmdbuf[0] = IPC_MakeHeader(0x0B, 13, 0);
        cmdbuf[1] = 0;
        memcpy(&cmdbuf[2], st, 0x30);
        return;
    }
    case 0x0D: // GetNodeInformation
    {
        u16 reqNode = (u16)cmdbuf[1];
        u8 semanticHostInfo[UDS_RELAY_V3_NODE_INFO_SIZE];
        bool haveSemanticHost = false;
        RecursiveLock_Lock(&s_connLock);
        RecursiveLock_Lock(&s_beaconLock);
        if (reqNode >= 1u && reqNode <= 16u && s_relayV3Role.active &&
            (s_relayV3Role.peers.valid_mask &
             (u16)(1u << (reqNode - 1u))) != 0u)
        {
            memcpy(semanticHostInfo,
                   s_relayV3Role.peers.node_info[reqNode - 1u],
                   sizeof(semanticHostInfo));
            haveSemanticHost = true;
        }
        else if (reqNode == 1u &&
                 s_relayV3Role.kind == RELAY_V3_ROLE_HOST &&
                 (s_relayV3Role.pending || s_relayV3Role.active) &&
                 !s_relayV3Role.retire_pending &&
                 s_connStatus == UDS_STATUS_HOST &&
                 s_connReason == UDS_REASON_ESTABLISHED &&
                 s_ourNodeID == 1u)
        {
            /* Native UDS exposes the host's own NodeInfo before the relay peer map. */
            memcpy(semanticHostInfo, s_relayV3Role.own_node_info,
                   sizeof(semanticHostInfo));
            haveSemanticHost = true;
        }
        else if (reqNode == 1u && s_isSpectator &&
                 s_connStatus == UDS_STATUS_SPECTATOR &&
                 s_relayV3SelectedRoom.valid)
        {
            memcpy(semanticHostInfo,
                   s_relayV3SelectedRoom.host_node_info,
                   sizeof(semanticHostInfo));
            haveSemanticHost = true;
        }
        RecursiveLock_Unlock(&s_beaconLock);
        RecursiveLock_Unlock(&s_connLock);
        u8 ni[0x28];
        u32 result = 0;
        memset(ni, 0, sizeof(ni));
        if (haveSemanticHost)
        {
            memcpy(ni, semanticHostInfo, sizeof(ni));
        }
        else
            result = 0xC90113FAu;
        if (result == 0u)
            *(u16 *)(ni + 0x20) = reqNode;
        cmdbuf[0] = IPC_MakeHeader(0x0D, 11, 0);
        cmdbuf[1] = result;
        memcpy(&cmdbuf[2], ni, sizeof(ni));
        return;
    }
    case 0x0F: // RecvBeaconBroadcastData
    {
        // Request: [17]=SharedHandles(1), [18]=scan event,
        // [19]=mapped W-buffer descriptor, [20]=mapped buffer pointer.
        /* Echo the mapped-buffer descriptor in the reply to release the mapping. */
        Handle scanEvent = (Handle)cmdbuf[18];
        u32 bufDesc = cmdbuf[19];
        u32 bufPtr  = cmdbuf[20];
        u32 wlanCommId = cmdbuf[15];
        u8 id8 = (u8)cmdbuf[16];
        u32 bufSz = bufDesc >> 4; // IPC_Desc_Buffer encodes (size << 4) | permissions
        if (bufSz > 0x40000u) bufSz = 0x40000u;
        if (bufPtr != 0 && bufSz != 0)
        {
            memset((void *)bufPtr, 0, bufSz);
            u8 count = 0;
            bool built = relayV3BuildScan(wlanCommId, id8, (u8 *)bufPtr,
                                          bufSz, &count);
            if (!built && bufSz >= 12u)
            {
                u32 *header = (u32 *)bufPtr;
                header[0] = bufSz;
                header[1] = 12u;
                header[2] = 0u;
            }
        }
        /* Throttle repeated scans without holding UDS state locks. */
        svcSleepThread(UDS_BEACON_SCAN_INTERVAL_NS);
        if (scanEvent != 0)
        {
            svcSignalEvent(scanEvent);
            svcCloseHandle(scanEvent);  // copied handle, owned by this service
        }
        cmdbuf[0] = IPC_MakeHeader(0x0F, 1, 2);
        cmdbuf[1] = 0;
        cmdbuf[2] = bufDesc;
        cmdbuf[3] = bufPtr;
        return;
    }
    case 0x03: // Finalize
        hleCleanupFinalizeState();
        cmdbuf[0] = IPC_MakeHeader(0x03, 1, 0);
        cmdbuf[1] = 0;
        return;
    case 0x17: // SendTo
    {
        // Request: [2]=destination node [3]=data channel [5]=byte count; payload in static buffer 5.
        u16 dst     = (u16)cmdbuf[2];
        u8  channel = (u8)cmdbuf[3];
        u32 size    = cmdbuf[5];
        if (size > sizeof(s_sb5)) size = sizeof(s_sb5);
        if (size > RELAY_UDS_PAYLOAD_MAX) size = RELAY_UDS_PAYLOAD_MAX;
        if (relayV3SendToValuesValid(dst, channel))
        {
            u32 w, r;
            RecursiveLock_Lock(&s_connLock);
            RecursiveLock_Lock(&s_beaconLock);
            w = s_sendWrite;
            r = s_sendRead;
            if (w - r < SEND_RING_CAP)
            {
                SendEntry *se = &s_sendRing[w % SEND_RING_CAP];
                se->dst = dst; se->channel = channel; se->len = (u16)size;
                se->sendGeneration = 0;
                if (((s_relayV3Role.kind == RELAY_V3_ROLE_HOST &&
                      (s_relayV3Role.pending || s_relayV3Role.active)) ||
                     (s_relayV3Role.kind == RELAY_V3_ROLE_GUEST &&
                      s_relayV3Role.active)) &&
                    udsSendRouteCanTransmit(s_connStatus, s_connReason,
                                             s_ourNodeID, s_sessionId))
                {
                    se->sendGeneration = s_sendGeneration;
                }
                if (size) memcpy(se->data, s_sb5, size);
                s_sendWrite = w + 1;
            }
            RecursiveLock_Unlock(&s_beaconLock);
            RecursiveLock_Unlock(&s_connLock);
        }
        cmdbuf[0] = IPC_MakeHeader(0x17, 1, 0);
        cmdbuf[1] = 0;
        return;
    }
    case 0x14: // PullPacket
    {
        // Request: [1]=BindNodeID [2]=aligned_size>>2 [3]=size.
        // Reply includes static buffer 0 even when empty.
        u32 reqBindNodeID = cmdbuf[1];
        u32 reqSize = cmdbuf[3];
        u32 actual = 0;
        u16 src = 0;
        u8 currentRole = UDS_CONNECT_ROLE_INVALID;
        static UdsRecvFrameV3 frameV3;
        u8 currentScope[16] = {0};
        u32 nodeGenerations[16] = {0};
        u16 nodeMask = 0;
        RecursiveLock_Lock(&s_connLock);
        BindSlot *b = bindByNodeID(reqBindNodeID);
        RecursiveLock_Lock(&s_beaconLock);
        if (s_relayV3SelectedRoom.valid && s_isSpectator &&
            s_connStatus == UDS_STATUS_SPECTATOR &&
            s_connReason == UDS_REASON_ESTABLISHED)
        {
            memcpy(currentScope, s_relayV3SelectedRoom.room_id,
                   sizeof(currentScope));
            currentRole = UDS_CONNECT_ROLE_SPECTATOR;
            nodeGenerations[0] = 1u;
            nodeMask = 0x1u;
        }
        else if (s_relayV3Role.active &&
                 (s_connStatus == UDS_STATUS_HOST ||
                  s_connStatus == UDS_STATUS_CLIENT) &&
                 s_connReason == UDS_REASON_ESTABLISHED)
        {
            memcpy(currentScope, s_relayV3Role.scope,
                   sizeof(currentScope));
            memcpy(nodeGenerations,
                   s_relayV3Role.peers.node_generations,
                   sizeof(nodeGenerations));
            if (s_relayV3Role.kind == RELAY_V3_ROLE_HOST)
                nodeGenerations[0] = 1u;
            nodeMask = s_relayV3Role.peers.valid_mask;
            currentRole = UDS_CONNECT_ROLE_CLIENT;
        }
        RecursiveLock_Unlock(&s_beaconLock);
        if (b != NULL)
        {
            bool popped = udsRecvRingV3PopCurrent(&b->ring, currentScope,
                                                   currentRole, nodeGenerations,
                                                   nodeMask, &frameV3);
            if (popped)
            {
                u32 cap = sizeof(s_sb0);
                if (reqSize < cap) cap = reqSize;
                actual = frameV3.frame.len;
                if (actual > cap) actual = cap;
                src = frameV3.frame.src;
                if (actual) memcpy(s_sb0, frameV3.frame.data, actual);
            }
            if (b->channel == DLP_ADVERT_CHANNEL)
            {
                RecursiveLock_Lock(&s_beaconLock);
                bool reprime = relayV3DlpAdvertPrimeBindLocked(b);
                if (reprime && b->event != 0)
                    svcSignalEvent(b->event);
                RecursiveLock_Unlock(&s_beaconLock);
            }
        }
        RecursiveLock_Unlock(&s_connLock);
        cmdbuf[0] = IPC_MakeHeader(0x14, 3, 2);
        cmdbuf[1] = 0;
        cmdbuf[2] = actual;
        cmdbuf[3] = src;
        cmdbuf[4] = IPC_Desc_StaticBuffer(actual, 0);
        cmdbuf[5] = (u32)s_sb0;
        return;
    }
    case 0x13: // Unbind
    {
        u32 bindNodeID = cmdbuf[1];
        RecursiveLock_Lock(&s_connLock);
        BindSlot *b = bindByNodeID(bindNodeID);
        if (b != NULL)
        {
            b->used = false;
            /* Defer event reclamation; a quick rebind keeps existing waiters valid. */
            b->freedTick = svcGetSystemTick() >> 8;
        }
        RecursiveLock_Unlock(&s_connLock);
        cmdbuf[0] = IPC_MakeHeader(0x13, 5, 0);
        cmdbuf[1] = 0;
        cmdbuf[2] = bindNodeID;
        cmdbuf[3] = 0;
        cmdbuf[4] = 0;
        return;
    }
    case 0x1F: // DecryptBeaconData
    {
        u8 semanticHostInfo[UDS_RELAY_V3_NODE_INFO_SIZE];
        bool haveSemanticHost = false;
        RecursiveLock_Lock(&s_beaconLock);
        int roomIndex = udsRelayV3RoomsFindNetwork(&s_relayV3Rooms, s_sb1);
        if (roomIndex >= 0)
        {
            memcpy(semanticHostInfo,
                   s_relayV3Rooms.slots[roomIndex].host_node_info,
                   sizeof(semanticHostInfo));
            haveSemanticHost = true;
        }
        RecursiveLock_Unlock(&s_beaconLock);
        memset(s_sb0, 0, 0x280);
        // NodeInfo (LE): friend_code_seed@0(8), username[10]@8(u16),
        // padding@1C(4), network_node_id@20(u16), padding@22(6).
        if (haveSemanticHost)
            memcpy(s_sb0, semanticHostInfo, sizeof(semanticHostInfo));
        cmdbuf[0] = IPC_MakeHeader(0x1F, 1, 2);
        cmdbuf[1] = haveSemanticHost ? 0u : UDS_OUT_OF_RESOURCE;
        cmdbuf[2] = IPC_Desc_StaticBuffer(0x280, 0); // NodeInfo[16]
        cmdbuf[3] = (u32)s_sb0;
        return;
    }
    case 0x22: // ScanOnConnection
    {
        u32 bufDesc = cmdbuf[17];
        u32 bufPtr = cmdbuf[18];
        u32 bufSz = bufDesc >> 4;
        if (bufPtr != 0 && (bufDesc & 0xFu) == 0xCu &&
            bufSz >= 12u && bufSz <= 0x40000u)
        {
            u32 *bh = (u32 *)bufPtr;
            bh[0] = bufSz;
            bh[1] = 12u;
            bh[2] = 0u;
        }
        cmdbuf[0] = IPC_MakeHeader(0x22, 1, 2);
        cmdbuf[1] = 0;
        cmdbuf[2] = bufDesc;
        cmdbuf[3] = bufPtr;
        return;
    }
    default:
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, 0);
        cmdbuf[1] = 0;
        return;
    }
}

typedef struct {
    u32 cmdId;
    Handle sharedMemory;
    Handle scanEvent;
    u32 bufferDescriptor;
    u32 bufferPointer;
    bool hasSharedMemory;
    bool hasScanEvent;
    bool hasMappedBuffer;
} UdsIpcValidated;

static u32 relayV3TranslatedHandleCount(u32 descriptor)
{
    u32 kind = descriptor & 0x03FFFFFFu;
    if (kind != 0u && kind != 0x10u)
        return 0;
    return (descriptor >> 26) + 1u;
}

static bool relayV3ValidateCommand(u32 *cmdbuf, u32 cmdId,
                                   UdsIpcValidated *validated)
{
    memset(validated, 0, sizeof(*validated));
    validated->cmdId = cmdId;

#define UDS_IPC_HEADER_IS(normalWords, translateWords) \
    (cmdbuf[0] == IPC_MakeHeader(cmdId, normalWords, translateWords))

    switch (cmdId)
    {
    case 0x03:
    case 0x08:
    case 0x0A:
    case 0x0B:
    case 0x1A:
        return UDS_IPC_HEADER_IS(0, 0);
    case 0x05:
    case 0x0D:
        return UDS_IPC_HEADER_IS(1, 0);
    case 0x07:
        return UDS_IPC_HEADER_IS(2, 0);
    case 0x0F:
    {
        if (!UDS_IPC_HEADER_IS(16, 4))
            return false;
        u32 size = cmdbuf[1];
        if (cmdbuf[17] != IPC_Desc_SharedHandles(1) ||
            cmdbuf[18] == 0 || size > 0x40000u ||
            cmdbuf[19] != IPC_Desc_Buffer(size, IPC_BUFFER_W) ||
            (size != 0 && cmdbuf[20] == 0))
            return false;
        validated->scanEvent = (Handle)cmdbuf[18];
        validated->hasScanEvent = true;
        validated->bufferDescriptor = cmdbuf[19];
        validated->bufferPointer = cmdbuf[20];
        validated->hasMappedBuffer = true;
        return true;
    }
    case 0x12:
        return UDS_IPC_HEADER_IS(4, 0);
    case 0x13:
        return UDS_IPC_HEADER_IS(1, 0);
    case 0x14:
    {
        if (!UDS_IPC_HEADER_IS(3, 0) || cmdbuf[3] > sizeof(s_sb0))
            return false;
        u32 alignedSize = (cmdbuf[3] + 3u) & ~3u;
        return cmdbuf[2] == (alignedSize >> 2);
    }
    case 0x17:
    {
        if (!UDS_IPC_HEADER_IS(6, 2) || cmdbuf[5] > sizeof(s_sb5))
            return false;
        u32 alignedSize = (cmdbuf[5] + 3u) & ~3u;
        if (cmdbuf[4] != (alignedSize >> 2) ||
            cmdbuf[7] != IPC_Desc_StaticBuffer(alignedSize, 5) ||
            (alignedSize != 0 && cmdbuf[8] == 0))
            return false;
        return true;
    }
    case 0x1B:
        if (!UDS_IPC_HEADER_IS(12, 2) ||
            cmdbuf[13] != IPC_Desc_SharedHandles(1) || cmdbuf[14] == 0)
            return false;
        validated->sharedMemory = (Handle)cmdbuf[14];
        validated->hasSharedMemory = true;
        return true;
    case 0x1D:
    {
        if (!UDS_IPC_HEADER_IS(1, 4))
            return false;
        u32 passphraseSize = cmdbuf[1];
        return passphraseSize <= sizeof(s_sb0) &&
               cmdbuf[2] == IPC_Desc_StaticBuffer(0x108u, 1) &&
               cmdbuf[3] != 0 &&
               cmdbuf[4] == IPC_Desc_StaticBuffer(passphraseSize, 0) &&
               (passphraseSize == 0 || cmdbuf[5] != 0);
    }
    case 0x1E:
    {
        if (!UDS_IPC_HEADER_IS(2, 4))
            return false;
        u32 passphraseSize = cmdbuf[2];
        return passphraseSize <= sizeof(s_sb0) &&
               cmdbuf[3] == IPC_Desc_StaticBuffer(0x108u, 1) &&
               cmdbuf[4] != 0 &&
               cmdbuf[5] == IPC_Desc_StaticBuffer(passphraseSize, 0) &&
               (passphraseSize == 0 || cmdbuf[6] != 0);
    }
    case 0x1F:
        return UDS_IPC_HEADER_IS(0, 6) &&
               cmdbuf[1] == IPC_Desc_StaticBuffer(0x108u, 1) &&
               cmdbuf[2] != 0 &&
               cmdbuf[3] == IPC_Desc_StaticBuffer(0xFEu, 2) &&
               cmdbuf[4] != 0 &&
               cmdbuf[5] == IPC_Desc_StaticBuffer(0xFEu, 3) &&
               cmdbuf[6] != 0;
    case 0x21:
        return UDS_IPC_HEADER_IS(2, 0);
    case 0x22:
    {
        if (!UDS_IPC_HEADER_IS(16, 2))
            return false;
        u32 size = cmdbuf[1];
        if (size > 0x40000u ||
            cmdbuf[17] != IPC_Desc_Buffer(size, IPC_BUFFER_W) ||
            (size != 0 && cmdbuf[18] == 0))
            return false;
        validated->bufferDescriptor = cmdbuf[17];
        validated->bufferPointer = cmdbuf[18];
        validated->hasMappedBuffer = true;
        return true;
    }
    default:
        return false;
    }

#undef UDS_IPC_HEADER_IS
}

static void relayV3RejectMalformedCommand(u32 *cmdbuf, u32 cmdId,
                                          u32 result)
{
    u32 normalWords = (cmdbuf[0] >> 6) & 0x3Fu;
    u32 translateWords = cmdbuf[0] & 0x3Fu;
    u32 translateStart = normalWords + 1u;
    u32 mappedBufferCount = 0;
    u32 mappedDescriptors[32];
    u32 mappedPointers[32];

    if (translateStart <= 64u && translateWords <= 64u - translateStart)
    {
        u32 cursor = translateStart;
        u32 translateEnd = translateStart + translateWords;

        while (cursor < translateEnd)
        {
            u32 descriptor = cmdbuf[cursor++];
            u32 kind = descriptor & 0xFu;

            if (kind == 0u)
            {
                u32 handleCount = relayV3TranslatedHandleCount(descriptor);
                if (handleCount != 0u)
                {
                    if (handleCount > translateEnd - cursor)
                        break;

                    for (u32 i = 0; i < handleCount; i++)
                    {
                        Handle handle = (Handle)cmdbuf[cursor + i];
                        if (handle != 0)
                            svcCloseHandle(handle);
                    }
                    cursor += handleCount;
                    continue;
                }

                if (descriptor == IPC_Desc_CurProcessId() &&
                    cursor < translateEnd)
                {
                    cursor++;
                    continue;
                }
                break;
            }

            if (kind == 0x2u || kind == 0x4u || kind == 0x6u)
            {
                if (cursor >= translateEnd)
                    break;
                cursor++;
                continue;
            }

            if (kind == (0x8u | IPC_BUFFER_R) ||
                kind == (0x8u | IPC_BUFFER_W) ||
                kind == (0x8u | IPC_BUFFER_R | IPC_BUFFER_W))
            {
                if (cursor >= translateEnd || mappedBufferCount >= 32u)
                    break;
                mappedDescriptors[mappedBufferCount] = descriptor;
                mappedPointers[mappedBufferCount] = cmdbuf[cursor++];
                mappedBufferCount++;
                continue;
            }

            break;
        }
    }

    if (mappedBufferCount != 0u)
    {
        u32 replyTranslateWords = mappedBufferCount * 2u;
        cmdbuf[0] = IPC_MakeHeader(cmdId, 1, replyTranslateWords);
        cmdbuf[1] = result;
        for (u32 i = 0; i < mappedBufferCount; i++)
        {
            cmdbuf[2u + i * 2u] = mappedDescriptors[i];
            cmdbuf[3u + i * 2u] = mappedPointers[i];
        }
    }
    else
    {
        cmdbuf[0] = IPC_MakeHeader(0, 1, 0);
        cmdbuf[1] = result;
    }
}

static void relayV3RejectCommand(u32 *cmdbuf,
                                 const UdsIpcValidated *validated,
                                 u32 result)
{
    if (validated->hasScanEvent && validated->scanEvent != 0)
        svcCloseHandle(validated->scanEvent);
    if (validated->hasSharedMemory && validated->sharedMemory != 0)
        svcCloseHandle(validated->sharedMemory);

    cmdbuf[0] = IPC_MakeHeader(validated->cmdId, 1,
                               validated->hasMappedBuffer ? 2 : 0);
    cmdbuf[1] = result;
    if (validated->hasMappedBuffer)
    {
        cmdbuf[2] = validated->bufferDescriptor;
        cmdbuf[3] = validated->bufferPointer;
    }
}

void UdsRedirect_HandleCommands(void *ctx)
{
    (void)ctx;
    u32 *cmdbuf = getThreadCommandBuffer();
    u32 cmdId = (cmdbuf[0] >> 16) & 0xFFFFu;
    setupStaticBuffers();

    UdsIpcValidated validated;
    if (!relayV3ValidateCommand(cmdbuf, cmdId, &validated))
    {
        relayV3RejectMalformedCommand(cmdbuf, cmdId, 0xD9001830u);
        return;
    }

    if (!s_proxyEnabled || s_proxyConfigStatus != UDS_PROXY_CONFIG_OK)
    {
        relayV3RejectCommand(cmdbuf, &validated, UDS_OUT_OF_RESOURCE);
        return;
    }

    hleHandle(cmdbuf, cmdId);
}
