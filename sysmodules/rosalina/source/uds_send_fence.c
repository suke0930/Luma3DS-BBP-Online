/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "uds_send_fence.h"

#include <stdint.h>

uint8_t udsConnectTypeRole(uint8_t connection_type)
{
    if (connection_type == UDS_CONNECT_ROLE_CLIENT ||
        connection_type == UDS_CONNECT_ROLE_SPECTATOR)
        return connection_type;
    return UDS_CONNECT_ROLE_INVALID;
}

uint32_t udsSendGenerationNext(uint32_t generation)
{
    if (generation == 0u || generation == UINT32_MAX)
        return 1u;
    return generation + 1u;
}

bool udsJoinRetryDue(bool in_flight,
                     uint64_t now_tick,
                     uint64_t sent_tick,
                     uint64_t retry_ticks)
{
    return in_flight && sent_tick != 0u && retry_ticks != 0u &&
           now_tick - sent_tick >= retry_ticks;
}

bool udsClientRouteNeedsRejoin(uint32_t status,
                               uint32_t reason,
                               uint16_t node,
                               uint32_t session)
{
    bool established = status == UDS_SEND_STATUS_CLIENT ||
                       status == UDS_SEND_STATUS_SPECTATOR;
    return established && reason == UDS_SEND_REASON_ESTABLISHED &&
           node != 0u && session != 0u;
}

bool udsSendRouteCanTransmit(uint32_t status,
                             uint32_t reason,
                             uint16_t node,
                             uint32_t session)
{
    if (udsClientRouteNeedsRejoin(status, reason, node, session))
        return true;
    return status == UDS_SEND_STATUS_HOST &&
           reason == UDS_SEND_REASON_ESTABLISHED &&
           node == 1u && session == 0u;
}

bool udsSendGenerationIsCurrent(uint32_t entry_generation,
                                uint32_t current_generation,
                                uint32_t status,
                                uint32_t reason,
                                uint16_t node,
                                uint32_t session)
{
    return entry_generation != 0u && entry_generation == current_generation &&
           udsSendRouteCanTransmit(status, reason, node, session);
}
