/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BBP_RELAY_ROOMS_H
#define BBP_RELAY_ROOMS_H

#include <stdbool.h>
#include <stdint.h>

#include "uds_beacon_scan.h"

#define UDS_RELAY_V3_ROOM_LIMIT 4u
#define UDS_RELAY_V3_NETWORK_INFO_SIZE 0x108u
#define UDS_RELAY_V3_NODE_INFO_SIZE 0x28u

typedef struct {
    uint8_t room_id[16];
    uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE];
    uint8_t host_node_info[UDS_RELAY_V3_NODE_INFO_SIZE];
    size_t beacon_length;
    uint8_t beacon[1024];
    UdsBeaconCandidateIdentity identity;
    uint64_t generation;
    bool valid;
} UdsRelayV3Room;

typedef struct {
    uint8_t room_id[16];
    uint64_t generation;
    bool valid;
} UdsRelayV3RoomLatch;

typedef struct {
    uint64_t list_version;
    uint8_t count;
    UdsRelayV3Room slots[UDS_RELAY_V3_ROOM_LIMIT];
    UdsRelayV3RoomLatch latches[UDS_RELAY_V3_ROOM_LIMIT];
} UdsRelayV3Rooms;

bool udsRelayV3RoomsApply(UdsRelayV3Rooms *rooms, const uint8_t *body,
                          uint16_t body_length);
int udsRelayV3RoomsFindNetwork(const UdsRelayV3Rooms *rooms,
                               const uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE]);
int udsRelayV3RoomsFindLatchedNetwork(
    const UdsRelayV3Rooms *rooms,
    const uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE]);
int udsRelayV3RoomsTakeLatchedNetwork(
    UdsRelayV3Rooms *rooms,
    const uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE]);
void udsRelayV3RoomsExpireVisibility(UdsRelayV3Rooms *rooms);
bool udsRelayV3RoomsBuildScan(UdsRelayV3Rooms *rooms,
                              uint32_t wlan_comm_id, uint8_t id8,
                              uint8_t *output, size_t output_capacity,
                              uint8_t *out_count);

#endif
