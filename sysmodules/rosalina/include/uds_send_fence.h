/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UDS_SEND_FENCE_H
#define UDS_SEND_FENCE_H

#include <stdbool.h>
#include <stdint.h>

#define UDS_SEND_STATUS_CLIENT 9u
#define UDS_SEND_STATUS_SPECTATOR 10u
#define UDS_SEND_STATUS_HOST 6u
#define UDS_SEND_REASON_ESTABLISHED 1u

#define UDS_CONNECT_ROLE_INVALID 0u
#define UDS_CONNECT_ROLE_CLIENT 1u
#define UDS_CONNECT_ROLE_SPECTATOR 2u

uint8_t udsConnectTypeRole(uint8_t connection_type);

/* Generation zero marks an entry that must never be sent. */
uint32_t udsSendGenerationNext(uint32_t generation);

bool udsJoinRetryDue(bool in_flight,
                     uint64_t now_tick,
                     uint64_t sent_tick,
                     uint64_t retry_ticks);

bool udsClientRouteNeedsRejoin(uint32_t status,
                               uint32_t reason,
                               uint16_t node,
                               uint32_t session);

bool udsSendRouteCanTransmit(uint32_t status,
                             uint32_t reason,
                             uint16_t node,
                             uint32_t session);

bool udsSendGenerationIsCurrent(uint32_t entry_generation,
                                uint32_t current_generation,
                                uint32_t status,
                                uint32_t reason,
                                uint16_t node,
                                uint32_t session);

#endif
