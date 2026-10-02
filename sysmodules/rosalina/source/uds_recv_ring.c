/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "uds_recv_ring.h"

#include <string.h>

static uint32_t ringByteOffset(uint32_t start_slot)
{
    return start_slot * UDS_RECV_RING_SLOT_SIZE;
}

static void writeBytes(UdsRecvRing *ring, uint32_t start_slot, uint32_t offset,
                       const void *source, uint32_t length)
{
    uint32_t capacity = ring->capacity_slots * UDS_RECV_RING_SLOT_SIZE;
    uint32_t position = (ringByteOffset(start_slot) + offset) % capacity;
    const uint8_t *src = (const uint8_t *)source;

    while (length != 0u)
    {
        uint32_t chunk = capacity - position;
        if (chunk > length)
            chunk = length;
        memcpy(ring->storage + position, src, chunk);
        src += chunk;
        length -= chunk;
        position = (position + chunk) % capacity;
    }
}

static void readBytes(const UdsRecvRing *ring, uint32_t start_slot,
                      uint32_t offset, void *destination, uint32_t length)
{
    uint32_t capacity = ring->capacity_slots * UDS_RECV_RING_SLOT_SIZE;
    uint32_t position = (ringByteOffset(start_slot) + offset) % capacity;
    uint8_t *dst = (uint8_t *)destination;

    while (length != 0u)
    {
        uint32_t chunk = capacity - position;
        if (chunk > length)
            chunk = length;
        memcpy(dst, ring->storage + position, chunk);
        dst += chunk;
        length -= chunk;
        position = (position + chunk) % capacity;
    }
}

uint16_t udsRecvRingSlotCost(uint32_t payload_len)
{
    if (payload_len > UDS_RECV_RING_MAX_PAYLOAD)
        return 0u;
    uint32_t slots = (payload_len + UDS_RECV_RING_SLOT_SIZE + 7u +
                      UDS_RECV_RING_SLOT_SIZE - 1u) /
                     UDS_RECV_RING_SLOT_SIZE;
    if (slots < 2u)
        slots = 2u;
    return slots > UDS_RECV_RING_MAX_SLOTS ? 0u : (uint16_t)slots;
}

bool udsRecvRingInit(UdsRecvRing *ring, uint32_t capacity_bytes)
{
    uint32_t slots;

    if (ring == NULL || capacity_bytes == 0u ||
        capacity_bytes > UDS_RECV_RING_MAX_SLOTS * UDS_RECV_RING_SLOT_SIZE)
        return false;
    slots = capacity_bytes / UDS_RECV_RING_SLOT_SIZE;
    if (slots < 2u)
        return false;
    memset(ring, 0, sizeof(*ring));
    ring->capacity_slots = (uint16_t)slots;
    return true;
}

void udsRecvRingReset(UdsRecvRing *ring)
{
    uint16_t capacity_slots;

    if (ring == NULL)
        return;
    capacity_slots = ring->capacity_slots;
    memset(ring, 0, sizeof(*ring));
    ring->capacity_slots = capacity_slots;
}

bool udsRecvRingCanReserve(const UdsRecvRing *ring, const uint16_t *slot_costs,
                           uint16_t count)
{
    uint32_t write_slot;
    uint32_t used_slots;
    uint16_t frame_count;
    uint16_t i;

    if (ring == NULL || slot_costs == NULL || count == 0u ||
        ring->capacity_slots < 2u)
        return false;
    write_slot = ring->write_slot;
    used_slots = ring->used_slots;
    frame_count = ring->frame_count;
    for (i = 0; i < count; i++)
    {
        uint16_t cost = slot_costs[i];
        if (cost == 0u || cost > ring->capacity_slots ||
            frame_count == UDS_RECV_RING_MAX_FRAMES ||
            used_slots + cost > ring->capacity_slots)
            return false;
        used_slots += cost;
        frame_count++;
        write_slot = (write_slot + cost) % ring->capacity_slots;
    }
    return true;
}

static void dropOldest(UdsRecvRing *ring)
{
    const UdsRecvFrameMeta *meta;

    if (ring->frame_count == 0u)
        return;
    meta = &ring->meta[ring->read_frame % UDS_RECV_RING_MAX_FRAMES];
    ring->used_slots -= meta->slot_cost;
    ring->read_frame++;
    ring->frame_count--;
    if (ring->frame_count != 0u)
        ring->read_slot =
            ring->meta[ring->read_frame % UDS_RECV_RING_MAX_FRAMES].start_slot;
    else
        ring->read_slot = ring->write_slot;
}

static void copyFrame(const UdsRecvRing *ring, uint32_t frame_index,
                      UdsRecvFrame *out)
{
    const UdsRecvFrameMeta *meta =
        &ring->meta[frame_index % UDS_RECV_RING_MAX_FRAMES];
    uint8_t header[8];

    readBytes(ring, meta->start_slot, 0u, header, sizeof(header));
    memcpy(&out->src, header, sizeof(out->src));
    memcpy(&out->dst, header + 2u, sizeof(out->dst));
    out->channel = header[4];
    out->reserved = header[5];
    memcpy(&out->len, header + 6u, sizeof(out->len));
    out->guest_membership_token = meta->guest_membership_token;
    out->owner_role = meta->owner_role;
    out->slot_cost = meta->slot_cost;
    if (out->len != 0u)
        readBytes(ring, meta->start_slot, 8u, out->data, out->len);
}

bool udsRecvRingPush(UdsRecvRing *ring, uint16_t src, uint16_t dst,
                     uint8_t channel, const uint8_t *payload,
                     uint16_t payload_len, uint64_t guest_membership_token,
                     uint8_t owner_role)
{
    UdsRecvFrameMeta *meta;
    uint16_t slot_cost;
    uint32_t start_slot;

    if (ring == NULL || payload == NULL || payload_len == 0u ||
        payload_len > UDS_RECV_RING_MAX_PAYLOAD ||
        ring->capacity_slots < 2u)
        return false;
    slot_cost = udsRecvRingSlotCost(payload_len);
    if (slot_cost == 0u || slot_cost > ring->capacity_slots)
        return false;

    start_slot = ring->write_slot;
    while (ring->frame_count == UDS_RECV_RING_MAX_FRAMES ||
           ring->used_slots + slot_cost > ring->capacity_slots)
        dropOldest(ring);

    uint8_t header[8] = { 0 };
    memcpy(header, &src, sizeof(src));
    memcpy(header + 2u, &dst, sizeof(dst));
    header[4] = channel;
    memcpy(header + 6u, &payload_len, sizeof(payload_len));
    writeBytes(ring, start_slot, 0u, header, sizeof(header));
    writeBytes(ring, start_slot, 8u, payload, payload_len);

    meta = &ring->meta[ring->write_frame % UDS_RECV_RING_MAX_FRAMES];
    meta->start_slot = start_slot;
    meta->slot_cost = slot_cost;
    meta->owner_role = owner_role;
    meta->reserved = 0u;
    meta->guest_membership_token = guest_membership_token;
    ring->write_frame++;
    ring->frame_count++;
    ring->used_slots += slot_cost;
    ring->write_slot = (start_slot + slot_cost) % ring->capacity_slots;
    if (ring->frame_count == 1u)
        ring->read_slot = start_slot;
    return true;
}

bool udsRecvRingPeek(const UdsRecvRing *ring, UdsRecvFrame *out)
{
    if (ring == NULL || out == NULL || ring->frame_count == 0u)
        return false;
    copyFrame(ring, ring->read_frame, out);
    return true;
}

bool udsRecvRingPop(UdsRecvRing *ring, UdsRecvFrame *out)
{
    if (ring == NULL || out == NULL || ring->frame_count == 0u)
        return false;
    copyFrame(ring, ring->read_frame, out);
    dropOldest(ring);
    return true;
}

bool udsRecvRingPopCurrent(UdsRecvRing *ring, uint64_t guest_membership_token,
                           uint8_t owner_role, UdsRecvFrame *out)
{
    if (ring == NULL || out == NULL)
        return false;
    while (ring->frame_count != 0u)
    {
        if (!udsRecvRingPeek(ring, out))
            return false;
        if (out->guest_membership_token == guest_membership_token &&
            out->owner_role == owner_role)
            return udsRecvRingPop(ring, out);
        dropOldest(ring);
    }
    return false;
}

uint16_t udsRecvRingUsedSlots(const UdsRecvRing *ring)
{
    return ring == NULL ? 0u : (uint16_t)ring->used_slots;
}

size_t udsRecvRingV3Size(void)
{
    return sizeof(UdsRecvRingV3);
}

bool udsRecvRingV3Init(UdsRecvRingV3 *ring, uint32_t capacity_bytes)
{
    if (ring == NULL)
        return false;
    memset(ring, 0, sizeof(*ring));
    return udsRecvRingInit(&ring->ring, capacity_bytes);
}

bool udsRecvRingV3PushCurrent(UdsRecvRingV3 *ring, uint16_t src, uint16_t dst,
                              uint8_t channel, const uint8_t *payload,
                              uint16_t payload_len, const uint8_t packet_scope[16],
                              const uint8_t current_scope[16],
                              uint32_t source_generation,
                              uint32_t expected_source_generation,
                              uint8_t owner_role)
{
    uint32_t index;
    if (ring == NULL || packet_scope == NULL || current_scope == NULL ||
        memcmp(packet_scope, current_scope, 16u) != 0 ||
        source_generation == 0u ||
        source_generation != expected_source_generation)
        return false;
    index = ring->ring.write_frame % UDS_RECV_RING_MAX_FRAMES;
    if (!udsRecvRingPush(&ring->ring, src, dst, channel, payload, payload_len,
                         0u, owner_role))
        return false;
    memcpy(ring->scope[index], packet_scope, 16u);
    ring->source_generation[index] = source_generation;
    return true;
}

bool udsRecvRingV3PopCurrent(UdsRecvRingV3 *ring,
                             const uint8_t current_scope[16],
                             uint8_t owner_role,
                             const uint32_t node_generations[16],
                             uint16_t node_mask, UdsRecvFrameV3 *out)
{
    if (ring == NULL || current_scope == NULL || node_generations == NULL ||
        out == NULL)
        return false;
    while (ring->ring.frame_count != 0u)
    {
        uint32_t index = ring->ring.read_frame % UDS_RECV_RING_MAX_FRAMES;
        if (!udsRecvRingPeek(&ring->ring, &out->frame))
            return false;
        bool current = out->frame.owner_role == owner_role &&
            out->frame.src >= 1u && out->frame.src <= 16u &&
            (node_mask & (uint16_t)(1u << (out->frame.src - 1u))) != 0u &&
            memcmp(ring->scope[index], current_scope, 16u) == 0 &&
            ring->source_generation[index] ==
                node_generations[out->frame.src - 1u];
        if (!udsRecvRingPop(&ring->ring, &out->frame))
            return false;
        if (current)
        {
            memcpy(out->scope, ring->scope[index], 16u);
            out->source_generation = ring->source_generation[index];
            return true;
        }
    }
    return false;
}
