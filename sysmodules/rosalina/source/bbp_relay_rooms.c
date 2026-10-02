/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "bbp_relay_rooms.h"

#include "bbp_relay_message.h"

#include <string.h>

static uint16_t readLe16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint64_t readLe64(const uint8_t *p)
{
    uint64_t value = 0u;
    for (unsigned i = 0u; i < 8u; i++)
        value |= (uint64_t)p[i] << (i * 8u);
    return value;
}

static void writeLe32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static bool nonzero(const uint8_t *data, size_t length)
{
    uint8_t value = 0u;
    for (size_t i = 0u; i < length; i++)
        value |= data[i];
    return value != 0u;
}

static bool sameRooms(const UdsRelayV3Rooms *a, const UdsRelayV3Rooms *b)
{
    if (a->count != b->count)
        return false;
    for (uint8_t i = 0u; i < a->count; i++)
    {
        if (memcmp(a->slots[i].room_id, b->slots[i].room_id, 16u) != 0 ||
            memcmp(a->slots[i].network_info, b->slots[i].network_info,
                   UDS_RELAY_V3_NETWORK_INFO_SIZE) != 0 ||
            memcmp(a->slots[i].host_node_info, b->slots[i].host_node_info,
                   UDS_RELAY_V3_NODE_INFO_SIZE) != 0)
            return false;
    }
    return true;
}

static int findRoomId(const UdsRelayV3Rooms *rooms, const uint8_t room_id[16])
{
    for (uint8_t i = 0u; i < rooms->count; i++)
        if (memcmp(rooms->slots[i].room_id, room_id, 16u) == 0)
            return i;
    return -1;
}

bool udsRelayV3RoomsApply(UdsRelayV3Rooms *rooms, const uint8_t *body,
                          uint16_t body_length)
{
    UdsRelayV3Rooms next;
    if (rooms == NULL ||
        !udsRelayV3BodyValidate(UDS_RELAY_V3_PKT_ROOM_LIST, 0u, body, body_length))
        return false;
    memset(&next, 0, sizeof(next));
    next.list_version = readLe64(body);
    next.count = body[8];
    for (uint8_t i = 0u; i < next.count; i++)
    {
        const uint8_t *entry = body + 16u + (size_t)i * 0x140u;
        UdsRelayV3Room *slot = &next.slots[i];
        memcpy(slot->room_id, entry, 16u);
        memcpy(slot->network_info, entry + 16u, sizeof(slot->network_info));
        memcpy(slot->host_node_info, entry + 16u + sizeof(slot->network_info),
               sizeof(slot->host_node_info));
        bool duplicate = false;
        for (uint8_t previous = 0u; previous < i; previous++)
            duplicate |= memcmp(next.slots[previous].room_id,
                                slot->room_id, 16u) == 0;
        if (duplicate || !nonzero(slot->room_id, 16u) ||
            slot->network_info[0x1Du] < 2u || slot->network_info[0x1Du] > 16u ||
            readLe16(slot->host_node_info + 0x20u) != 1u ||
            !udsBeaconBuildSemanticFrame(slot->network_info,
                                         UDS_RELAY_V3_NETWORK_INFO_SIZE +
                                             UDS_RELAY_V3_NODE_INFO_SIZE,
                                         slot->beacon, sizeof(slot->beacon),
                                         &slot->beacon_length, &slot->identity))
            return false;
        slot->valid = true;
    }
    for (uint8_t i = 1u; i < next.count; i++)
    {
        for (uint8_t j = i;
             j > 0u && memcmp(next.slots[j].room_id,
                              next.slots[j - 1u].room_id, 16u) < 0;
             j--)
        {
            uint8_t *left = (uint8_t *)&next.slots[j - 1u];
            uint8_t *right = (uint8_t *)&next.slots[j];
            for (size_t byte = 0u; byte < sizeof(UdsRelayV3Room); byte++)
            {
                uint8_t value = left[byte];
                left[byte] = right[byte];
                right[byte] = value;
            }
        }
    }
    if (rooms->list_version != 0u)
    {
        if (next.list_version < rooms->list_version)
            return false;
        if (next.list_version == rooms->list_version &&
            !sameRooms(rooms, &next))
            return false;
    }
    for (uint8_t i = 0u; i < next.count; i++)
    {
        int old = findRoomId(rooms, next.slots[i].room_id);
        next.slots[i].generation =
            old >= 0 &&
            memcmp(rooms->slots[old].network_info,
                   next.slots[i].network_info,
                   UDS_RELAY_V3_NETWORK_INFO_SIZE) == 0 &&
            memcmp(rooms->slots[old].host_node_info,
                   next.slots[i].host_node_info,
                   UDS_RELAY_V3_NODE_INFO_SIZE) == 0
                ? rooms->slots[old].generation
                : (next.list_version != 0u ? next.list_version : 1u);
    }
    uint8_t latch = 0u;
    for (uint8_t i = 0u; i < UDS_RELAY_V3_ROOM_LIMIT; i++)
    {
        if (!rooms->latches[i].valid)
            continue;
        int slot = findRoomId(&next, rooms->latches[i].room_id);
        if (slot >= 0 && next.slots[slot].generation ==
                             rooms->latches[i].generation)
            next.latches[latch++] = rooms->latches[i];
    }
    *rooms = next;
    return true;
}

int udsRelayV3RoomsFindNetwork(const UdsRelayV3Rooms *rooms,
                               const uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE])
{
    int match = -1;
    if (rooms == NULL || network_info == NULL)
        return -1;
    for (uint8_t i = 0u; i < rooms->count && i < UDS_RELAY_V3_ROOM_LIMIT; i++)
    {
        if (!rooms->slots[i].valid ||
            !udsBeaconCandidateMatchesCmd1E(
                network_info, UDS_RELAY_V3_NETWORK_INFO_SIZE,
                &rooms->slots[i].identity))
            continue;
        if (match >= 0)
            return -1;
        match = i;
    }
    return match;
}

int udsRelayV3RoomsTakeLatchedNetwork(
    UdsRelayV3Rooms *rooms,
    const uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE])
{
    int room = udsRelayV3RoomsFindLatchedNetwork(rooms, network_info);
    if (room < 0)
        return -1;
    for (uint8_t i = 0u; i < UDS_RELAY_V3_ROOM_LIMIT; i++)
    {
        if (rooms->latches[i].valid &&
            rooms->latches[i].generation == rooms->slots[room].generation &&
            memcmp(rooms->latches[i].room_id,
                   rooms->slots[room].room_id, 16u) == 0)
        {
            rooms->latches[i].valid = false;
            return room;
        }
    }
    return -1;
}

int udsRelayV3RoomsFindLatchedNetwork(
    const UdsRelayV3Rooms *rooms,
    const uint8_t network_info[UDS_RELAY_V3_NETWORK_INFO_SIZE])
{
    int room = udsRelayV3RoomsFindNetwork(rooms, network_info);
    if (room < 0)
        return -1;
    for (uint8_t i = 0u; i < UDS_RELAY_V3_ROOM_LIMIT; i++)
        if (rooms->latches[i].valid &&
            rooms->latches[i].generation == rooms->slots[room].generation &&
            memcmp(rooms->latches[i].room_id,
                   rooms->slots[room].room_id, 16u) == 0)
            return room;
    return -1;
}

void udsRelayV3RoomsExpireVisibility(UdsRelayV3Rooms *rooms)
{
    if (rooms == NULL)
        return;
    for (uint8_t i = 0u; i < UDS_RELAY_V3_ROOM_LIMIT; i++)
    {
        rooms->slots[i].valid = false;
        rooms->latches[i].valid = false;
    }
}

bool udsRelayV3RoomsBuildScan(UdsRelayV3Rooms *rooms,
                              uint32_t wlan_comm_id, uint8_t id8,
                              uint8_t *output, size_t output_capacity,
                              uint8_t *out_count)
{
    size_t total = 12u;
    uint8_t count = 0u;
    UdsRelayV3RoomLatch latches[UDS_RELAY_V3_ROOM_LIMIT] = {0};
    if (rooms == NULL || output == NULL || out_count == NULL ||
        output_capacity < total || output_capacity > UINT32_MAX)
        return false;
    for (uint8_t i = 0u; i < rooms->count && i < UDS_RELAY_V3_ROOM_LIMIT; i++)
    {
        const UdsRelayV3Room *room = &rooms->slots[i];
        size_t entry_size = 0x1Cu + room->beacon_length;
        if (!room->valid ||
            !udsBeaconMatchesScanQuery(room->beacon, room->beacon_length,
                                       wlan_comm_id, id8) ||
            entry_size > output_capacity - total)
            continue;
        uint8_t *entry = output + total;
        memset(entry, 0, 0x1Cu);
        writeLe32(entry, (uint32_t)entry_size);
        entry[5] = (uint8_t)room->identity.channel;
        memcpy(entry + 8u, room->identity.host_mac, 6u);
        writeLe32(entry + 0x14u, (uint32_t)entry_size);
        writeLe32(entry + 0x18u, 0x1Cu);
        memcpy(entry + 0x1Cu, room->beacon, room->beacon_length);
        memcpy(latches[count].room_id, room->room_id, 16u);
        latches[count].generation = room->generation;
        latches[count].valid = true;
        total += entry_size;
        count++;
    }
    memcpy(rooms->latches, latches, sizeof(latches));
    writeLe32(output, (uint32_t)output_capacity);
    writeLe32(output + 4u, (uint32_t)total);
    writeLe32(output + 8u, count);
    *out_count = count;
    return true;
}
