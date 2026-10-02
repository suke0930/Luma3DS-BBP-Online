/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UDS_RECV_RING_H
#define UDS_RECV_RING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDS_RECV_RING_SLOT_SIZE 0x20u
#define UDS_RECV_RING_MAX_SLOTS 480u
#define UDS_RECV_RING_MAX_FRAMES 240u
#define UDS_RECV_RING_MAX_PAYLOAD 0x5C6u

typedef struct {
    uint32_t start_slot;
    uint16_t slot_cost;
    uint8_t owner_role;
    uint8_t reserved;
    uint64_t guest_membership_token;
} UdsRecvFrameMeta;

typedef struct {
    uint16_t src;
    uint16_t dst;
    uint8_t channel;
    uint8_t reserved;
    uint16_t len;
    uint64_t guest_membership_token;
    uint8_t owner_role;
    uint16_t slot_cost;
    uint8_t data[UDS_RECV_RING_MAX_PAYLOAD];
} UdsRecvFrame;

typedef struct {
    uint8_t storage[UDS_RECV_RING_MAX_SLOTS * UDS_RECV_RING_SLOT_SIZE];
    UdsRecvFrameMeta meta[UDS_RECV_RING_MAX_FRAMES];
    uint32_t write_slot;
    uint32_t read_slot;
    uint32_t write_frame;
    uint32_t read_frame;
    uint32_t used_slots;
    uint16_t capacity_slots;
    uint16_t frame_count;
} UdsRecvRing;

typedef struct {
    UdsRecvRing ring;
    uint8_t scope[UDS_RECV_RING_MAX_FRAMES][16];
    uint32_t source_generation[UDS_RECV_RING_MAX_FRAMES];
} UdsRecvRingV3;

typedef struct {
    UdsRecvFrame frame;
    uint8_t scope[16];
    uint32_t source_generation;
} UdsRecvFrameV3;

uint16_t udsRecvRingSlotCost(uint32_t payload_len);
bool udsRecvRingInit(UdsRecvRing *ring, uint32_t capacity_bytes);
void udsRecvRingReset(UdsRecvRing *ring);
bool udsRecvRingCanReserve(const UdsRecvRing *ring, const uint16_t *slot_costs,
                           uint16_t count);
bool udsRecvRingPush(UdsRecvRing *ring, uint16_t src, uint16_t dst,
                     uint8_t channel, const uint8_t *payload,
                     uint16_t payload_len, uint64_t guest_membership_token,
                     uint8_t owner_role);
bool udsRecvRingPeek(const UdsRecvRing *ring, UdsRecvFrame *out);
bool udsRecvRingPop(UdsRecvRing *ring, UdsRecvFrame *out);
bool udsRecvRingPopCurrent(UdsRecvRing *ring, uint64_t guest_membership_token,
                           uint8_t owner_role, UdsRecvFrame *out);
uint16_t udsRecvRingUsedSlots(const UdsRecvRing *ring);
size_t udsRecvRingV3Size(void);
bool udsRecvRingV3Init(UdsRecvRingV3 *ring, uint32_t capacity_bytes);
bool udsRecvRingV3PushCurrent(UdsRecvRingV3 *ring, uint16_t src, uint16_t dst,
                              uint8_t channel, const uint8_t *payload,
                              uint16_t payload_len, const uint8_t packet_scope[16],
                              const uint8_t current_scope[16],
                              uint32_t source_generation,
                              uint32_t expected_source_generation,
                              uint8_t owner_role);
bool udsRecvRingV3PopCurrent(UdsRecvRingV3 *ring,
                             const uint8_t current_scope[16],
                             uint8_t owner_role,
                             const uint32_t node_generations[16],
                             uint16_t node_mask, UdsRecvFrameV3 *out);

#endif
