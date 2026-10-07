/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "bbp_relay_message.h"

#include <string.h>

static uint16_t readLe16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t readLe32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t readLe64(const uint8_t *p)
{
    return (uint64_t)readLe32(p) | ((uint64_t)readLe32(p + 4u) << 32);
}

static void writeLe16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void writeLe32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void writeLe64(uint8_t *p, uint64_t value)
{
    writeLe32(p, (uint32_t)value);
    writeLe32(p + 4u, (uint32_t)(value >> 32));
}

static bool headerValid(const UdsRelayV3Header *header, size_t fragment_length)
{
    if (header == NULL || header->packet_type < 1u ||
        header->packet_type > UDS_RELAY_V3_PKT_UNREGISTER ||
        header->fragment_count < 1u || header->fragment_count > 2u ||
        header->fragment_index >= header->fragment_count ||
        header->logical_body_length > UDS_RELAY_V3_MAX_LOGICAL_BODY)
        return false;
    if (header->fragment_count == 1u)
        return header->fragment_id == 0u && header->fragment_index == 0u &&
               header->logical_body_length == fragment_length;
    if (header->fragment_id == 0u)
        return false;
    size_t expected = header->fragment_index + 1u < header->fragment_count
        ? UDS_RELAY_V3_MAX_FRAGMENT_BODY
        : header->logical_body_length - UDS_RELAY_V3_MAX_FRAGMENT_BODY;
    return expected != 0u && expected == fragment_length;
}

bool udsRelayV3HeaderEncode(uint8_t *out, size_t out_capacity,
                            const UdsRelayV3Header *header)
{
    if (out == NULL || out_capacity < UDS_RELAY_V3_HEADER_SIZE || header == NULL)
        return false;
    writeLe32(out, UDS_RELAY_V3_MAGIC);
    writeLe16(out + 4u, UDS_RELAY_V3_VERSION);
    out[6] = header->packet_type;
    out[7] = header->flags;
    memcpy(out + 8u, header->token, sizeof(header->token));
    writeLe32(out + 24u, header->fragment_id);
    out[28] = header->fragment_index;
    out[29] = header->fragment_count;
    writeLe16(out + 30u, header->logical_body_length);
    return true;
}

bool udsRelayV3HeaderDecode(const uint8_t *packet, size_t packet_length,
                            UdsRelayV3Header *out)
{
    if (packet == NULL || out == NULL || packet_length < UDS_RELAY_V3_HEADER_SIZE ||
        packet_length > UDS_RELAY_V3_MAX_DATAGRAM ||
        readLe32(packet) != UDS_RELAY_V3_MAGIC ||
        readLe16(packet + 4u) != UDS_RELAY_V3_VERSION)
        return false;
    out->packet_type = packet[6];
    out->flags = packet[7];
    memcpy(out->token, packet + 8u, sizeof(out->token));
    out->fragment_id = readLe32(packet + 24u);
    out->fragment_index = packet[28];
    out->fragment_count = packet[29];
    out->logical_body_length = readLe16(packet + 30u);
    return headerValid(out, packet_length - UDS_RELAY_V3_HEADER_SIZE);
}

size_t udsRelayV3ReassemblerSize(void)
{
    return sizeof(UdsRelayV3Reassembler);
}

void udsRelayV3ReassemblerInit(UdsRelayV3Reassembler *state)
{
    if (state != NULL)
        memset(state, 0, sizeof(*state));
}

static bool tokenEqual(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16u) == 0;
}

static bool signatureEqual(const UdsRelayV3Header *a,
                           const UdsRelayV3Header *b)
{
    return a->packet_type == b->packet_type && a->flags == b->flags &&
           tokenEqual(a->token, b->token) && a->fragment_id == b->fragment_id &&
           a->fragment_count == b->fragment_count &&
           a->logical_body_length == b->logical_body_length;
}

bool udsRelayV3ReassemblerPush(UdsRelayV3Reassembler *state,
                               const uint8_t *packet, size_t packet_length,
                               uint64_t now_ms, UdsRelayV3Message *out)
{
    UdsRelayV3Header header;
    UdsRelayV3ReassemblyEntry *entry = NULL;
    UdsRelayV3ReassemblyEntry *free_entry = NULL;
    const uint8_t *fragment;
    size_t fragment_length;
    uint8_t bit;

    if (state == NULL || out == NULL ||
        !udsRelayV3HeaderDecode(packet, packet_length, &header))
        return false;
    fragment = packet + UDS_RELAY_V3_HEADER_SIZE;
    fragment_length = packet_length - UDS_RELAY_V3_HEADER_SIZE;
    if (header.fragment_count == 1u)
    {
        out->header = header;
        out->body_length = header.logical_body_length;
        if (fragment_length != 0u)
            memcpy(out->body, fragment, fragment_length);
        return true;
    }

    for (size_t i = 0; i < UDS_RELAY_V3_MAX_REASSEMBLIES; i++)
    {
        UdsRelayV3ReassemblyEntry *candidate = &state->entries[i];
        if (candidate->used && now_ms - candidate->last_ms > 1000u)
            memset(candidate, 0, sizeof(*candidate));
        if (!candidate->used)
        {
            if (free_entry == NULL)
                free_entry = candidate;
        }
        else if (candidate->header.fragment_id == header.fragment_id &&
                 tokenEqual(candidate->header.token, header.token))
        {
            entry = candidate;
            break;
        }
    }
    if (entry == NULL)
    {
        if (free_entry == NULL)
            return false;
        entry = free_entry;
        memset(entry, 0, sizeof(*entry));
        entry->used = true;
        entry->header = header;
    }
    else if (!signatureEqual(&entry->header, &header))
    {
        memset(entry, 0, sizeof(*entry));
        return false;
    }

    bit = (uint8_t)(1u << header.fragment_index);
    size_t offset = (size_t)header.fragment_index * UDS_RELAY_V3_MAX_FRAGMENT_BODY;
    if ((entry->received_mask & bit) != 0u)
    {
        if (entry->fragment_lengths[header.fragment_index] != fragment_length ||
            memcmp(entry->body + offset, fragment, fragment_length) != 0)
            memset(entry, 0, sizeof(*entry));
        return false;
    }
    memcpy(entry->body + offset, fragment, fragment_length);
    entry->fragment_lengths[header.fragment_index] = (uint16_t)fragment_length;
    entry->received_mask |= bit;
    entry->last_ms = now_ms;
    if (entry->received_mask != (uint8_t)((1u << header.fragment_count) - 1u))
        return false;

    out->header = entry->header;
    out->body_length = entry->header.logical_body_length;
    memcpy(out->body, entry->body, out->body_length);
    memset(entry, 0, sizeof(*entry));
    return true;
}

uint32_t udsRelayV3Fnv1a32(const uint8_t *data, size_t length)
{
    uint32_t value = 0x811C9DC5u;
    if (data == NULL && length != 0u)
        return 0u;
    for (size_t i = 0; i < length; i++)
        value = (value ^ data[i]) * 0x01000193u;
    return value;
}

static bool bytesNonzero(const uint8_t *data, size_t length)
{
    uint8_t value = 0u;
    for (size_t i = 0; i < length; i++)
        value |= data[i];
    return value != 0u;
}

static bool hostDescriptorValid(const uint8_t *network, const uint8_t *node)
{
    return network != NULL && node != NULL && bytesNonzero(network, 6u) &&
           (network[0] & 1u) == 0u && network[6] != 0u &&
           network[8] == 1u &&
           memcmp(network + 0x0Cu, "\x00\x1f\x32\x15", 4u) == 0 &&
           network[0x1Cu] == 1u && network[0x1Du] >= 2u &&
           network[0x1Du] <= 16u && network[0x3Fu] <= 0xC8u &&
           readLe16(node + 0x20u) == 1u;
}

bool udsRelayV3HostDescriptorPrepare(uint8_t network_info[0x108],
                                     uint8_t host_node_info[0x28],
                                     const uint8_t mac[6])
{
    if (network_info == NULL || host_node_info == NULL || mac == NULL ||
        !bytesNonzero(mac, 6u) || (mac[0] & 1u) != 0u ||
        network_info[0x1Du] < 2u || network_info[0x1Du] > 16u)
        return false;
    memcpy(network_info, mac, 6u);
    network_info[6] = 11u;
    network_info[8] = 1u;
    memcpy(network_info + 0x0Cu, "\x00\x1f\x32\x15", 4u);
    network_info[0x1Cu] = 1u;
    writeLe16(host_node_info + 0x20u, 1u);
    return hostDescriptorValid(network_info, host_node_info);
}

bool udsRelayV3BodyValidate(uint8_t packet_type, uint8_t flags,
                            const uint8_t *body, uint16_t body_length)
{
    static const uint16_t fixed_lengths[22] = {
        0u, 0x30u, 0x10u, 0x18u, 0x148u, 0x18u, 0u, 0x20u,
        0x50u, 0u, 0u, 0x20u, 0x18u, 0x18u, 0x20u, 0x10u, 0x10u,
        8u, 8u, 20u, 20u, 0u
    };
    if (packet_type == UDS_RELAY_V3_PKT_UNREGISTER)
        return flags == 0u && body_length == 0u;
    if (body == NULL || packet_type < 1u || packet_type > UDS_RELAY_V3_PKT_UNREGISTER)
        return false;
    if (packet_type == UDS_RELAY_V3_PKT_UDS_DATA)
    {
        if (body_length < 32u || body[21] != 0u || !bytesNonzero(body, 16u))
            return false;
        uint16_t src = readLe16(body + 16u);
        uint16_t dst = readLe16(body + 18u);
        uint16_t payload_length = readLe16(body + 22u);
        uint32_t hash = readLe32(body + 24u);
        uint32_t generation = readLe32(body + 28u);
        uint8_t expected_flags = dst == 0xFFFFu
            ? UDS_RELAY_V3_FLAG_BROADCAST : UDS_RELAY_V3_FLAG_UNICAST;
        return flags == expected_flags && src >= 1u && src <= 16u &&
               (dst == 0xFFFFu || (dst >= 1u && dst <= 16u)) && body[20] != 0u &&
               generation != 0u && payload_length <= 0x5C6u &&
               body_length == (uint16_t)(32u + payload_length) &&
               hash == udsRelayV3Fnv1a32(body + 32u, payload_length);
    }
    if (flags != 0u)
        return false;
    if (packet_type == UDS_RELAY_V3_PKT_ROOM_LIST)
    {
        if (body_length < 16u || body[8] > 4u)
            return false;
        for (size_t i = 9u; i < 16u; i++)
            if (body[i] != 0u) return false;
        if (body_length != (uint16_t)(16u + (uint16_t)body[8] * 0x140u))
            return false;
        for (uint8_t i = 0u; i < body[8]; i++)
        {
            const uint8_t *entry = body + 16u + (size_t)i * 0x140u;
            if (!bytesNonzero(entry, 16u) ||
                !hostDescriptorValid(entry + 16u,
                                     entry + 16u + 0x108u))
                return false;
        }
        return true;
    }
    if (packet_type == UDS_RELAY_V3_PKT_PEER_MAP)
    {
        if (body_length < 40u || !bytesNonzero(body, 16u) ||
            !bytesNonzero(body + 16u, 16u) || body[34] < 1u || body[34] > 16u ||
            body[35] != 0u || readLe16(body + 32u) < 1u ||
            readLe16(body + 32u) > 16u ||
            body_length != (uint16_t)(40u + (uint16_t)body[34] * 48u))
            return false;
        uint16_t seen = 0u;
        for (uint8_t i = 0u; i < body[34]; i++)
        {
            const uint8_t *item = body + 40u + (size_t)i * 48u;
            uint16_t node = readLe16(item);
            if (node < 1u || node > 16u || readLe16(item + 2u) != 0u ||
                readLe32(item + 4u) == 0u || (seen & (uint16_t)(1u << (node - 1u))) != 0u)
                return false;
            seen |= (uint16_t)(1u << (node - 1u));
        }
        return true;
    }
    if (fixed_lengths[packet_type] == 0u ||
        body_length != fixed_lengths[packet_type])
        return false;
    switch (packet_type)
    {
    case 0x01u:
        return bytesNonzero(body, 16u) && bytesNonzero(body + 16u, 16u) &&
               readLe64(body + 32u) == UINT64_C(0x00040000000A0B00) &&
               body[41] == 0u &&
               readLe32(body + 44u) == 0u;
    case 0x02u:
        return bytesNonzero(body, 16u);
    case 0x03u:
        return readLe32(body + 20u) == 0u;
    case 0x04u:
        return readLe64(body) != 0u && bytesNonzero(body + 8u, 16u) &&
               hostDescriptorValid(body + 0x18u, body + 0x120u);
    case 0x05u:
        return readLe64(body) != 0u && bytesNonzero(body + 8u, 16u);
    case 0x07u:
    case 0x0Bu:
        if (readLe64(body) == 0u || !bytesNonzero(body + 8u, 16u) ||
            body[24] > 3u)
            return false;
        for (size_t i = 25u; i < 32u; i++) if (body[i] != 0u) return false;
        return true;
    case 0x08u:
        return readLe64(body) != 0u && bytesNonzero(body + 8u, 16u) &&
               bytesNonzero(body + 24u, 16u);
    case 0x0Cu:
        if (!bytesNonzero(body, 16u) || body[16] > 3u)
            return false;
        for (size_t i = 17u; i < 24u; i++) if (body[i] != 0u) return false;
        return true;
    case 0x0Du:
        return readLe32(body) >= 1u && readLe32(body) <= 9u &&
               (readLe32(body) != 9u || body[4] == UDS_RELAY_V3_PKT_REGISTER) &&
               (body[4] == 0x01u || body[4] == 0x04u || body[4] == 0x07u ||
                body[4] == 0x08u || body[4] == 0x0Bu) &&
               body[5] == 0u && body[6] == 0u && body[7] == 0u &&
               bytesNonzero(body + 8u, 16u);
    case 0x0Eu:
        if ((body[0] != 0x07u && body[0] != 0x0Bu) ||
            readLe64(body + 8u) == 0u || !bytesNonzero(body + 16u, 16u))
            return false;
        for (size_t i = 1u; i < 8u; i++) if (body[i] != 0u) return false;
        return true;
    case 0x0Fu:
    case 0x10u:
        return bytesNonzero(body, 16u);
    case UDS_RELAY_V3_PKT_PROBE:
    case UDS_RELAY_V3_PKT_PROBE_ACK:
        return bytesNonzero(body, 8u);
    case UDS_RELAY_V3_PKT_STATUS_QUERY:
        return bytesNonzero(body, 8u);
    case UDS_RELAY_V3_PKT_STATUS_REPLY:
        if (!bytesNonzero(body, 8u) ||
            readLe16(body + 10u) > readLe16(body + 8u) ||
            bytesNonzero(body + 17u, 3u))
            return false;
        for (size_t i = 12u; i < 17u; i++) if (body[i] > 4u) return false;
        return true;
    default:
        return false;
    }
}

bool udsRelayV3UuidV4Prepare(uint8_t identifier[16])
{
    if (identifier == NULL)
        return false;
    identifier[6] = (uint8_t)((identifier[6] & 0x0Fu) | 0x40u);
    identifier[8] = (uint8_t)((identifier[8] & 0x3Fu) | 0x80u);
    return true;
}

bool udsRelayV3UuidV4Valid(const uint8_t identifier[16])
{
    return identifier != NULL && bytesNonzero(identifier, 16u) &&
           (identifier[6] & 0xF0u) == 0x40u &&
           (identifier[8] & 0xC0u) == 0x80u;
}

bool udsRelayV3HostParse(const char *data, size_t length, uint8_t address[4],
                         uint16_t *port)
{
    uint32_t value = 0u;
    size_t i = 0u;
    if (data == NULL || address == NULL || port == NULL || length == 0u)
        return false;
    for (size_t octet = 0u; octet < 4u; octet++)
    {
        size_t digits = 0u;
        value = 0u;
        while (i < length && data[i] >= '0' && data[i] <= '9')
        {
            value = value * 10u + (uint32_t)(data[i++] - '0');
            if (++digits > 3u || value > 255u)
                return false;
        }
        if (digits == 0u || (octet < 3u && (i >= length || data[i++] != '.')))
            return false;
        address[octet] = (uint8_t)value;
    }
    value = 24873u;
    if (i < length && data[i] == ':')
    {
        size_t digits = 0u;
        value = 0u;
        i++;
        while (i < length && data[i] >= '0' && data[i] <= '9')
        {
            value = value * 10u + (uint32_t)(data[i++] - '0');
            if (++digits > 5u || value > 65535u)
                return false;
        }
        if (digits == 0u || value == 0u)
            return false;
    }
    for (; i < length; i++)
        if (data[i] != ' ' && data[i] != '\r' && data[i] != '\n' && data[i] != '\t')
            return false;
    *port = (uint16_t)value;
    return true;
}

bool udsRelayV3RegisterBodyBuild(uint8_t out[0x30], const uint8_t client_id[16],
                                 const uint8_t nonce[16], uint8_t channel,
                                 uint16_t pin)
{
    if (out == NULL || client_id == NULL || nonce == NULL ||
        channel > 4u || pin > 9999u ||
        !bytesNonzero(client_id, 16u) || !bytesNonzero(nonce, 16u))
        return false;
    memcpy(out, client_id, 16u);
    memcpy(out + 16u, nonce, 16u);
    writeLe64(out + 32u, UINT64_C(0x00040000000A0B00));
    out[40] = pin != 0u ? 1u : 0u;
    out[41] = 0u;
    writeLe16(out + 42u, pin != 0u ? pin : channel);
    writeLe32(out + 44u, 0u);
    return true;
}

bool udsRelayV3StatusQueryPrepare(uint8_t out[20], const uint8_t nonce[8])
{
    if (out == NULL || nonce == NULL || !bytesNonzero(nonce, 8u))
        return false;
    memcpy(out, nonce, 8u);
    memset(out + 8u, 0, 12u);
    out[8] = UDS_RELAY_V3_STATUS_EXTENSION_VERSION;
    writeLe16(out + 9u, UDS_RELAY_V3_STATUS_CAP_U16_COUNTS);
    return true;
}

bool udsRelayV3QueryReplyMatches(const uint8_t *packet, size_t length,
                                  uint8_t expected_type, const uint8_t nonce[8])
{
    UdsRelayV3Header header;
    if (nonce == NULL ||
        (expected_type != UDS_RELAY_V3_PKT_PROBE_ACK &&
         expected_type != UDS_RELAY_V3_PKT_STATUS_REPLY) ||
        !udsRelayV3HeaderDecode(packet, length, &header) ||
        header.packet_type != expected_type || header.fragment_count != 1u ||
        memcmp(header.token, UDS_RELAY_V3_ADMISSION_MARKER, 16u) != 0)
        return false;
    const uint8_t *body = packet + UDS_RELAY_V3_HEADER_SIZE;
    return udsRelayV3BodyValidate(expected_type, header.flags, body,
                                  header.logical_body_length) &&
           memcmp(body, nonce, 8u) == 0;
}

bool udsRelayV3HeartbeatBodyBuild(uint8_t out[0x18], const uint8_t scope[16],
                                  uint32_t roster_version)
{
    if (out == NULL || scope == NULL)
        return false;
    memcpy(out, scope, 16u);
    writeLe32(out + 16u, roster_version);
    writeLe32(out + 20u, 0u);
    return true;
}

uint32_t udsRelayV3RetryDelayMs(uint32_t attempt)
{
    return attempt == 0u ? 250u : attempt == 1u ? 500u : 1000u;
}

uint64_t udsRelayV3DeadlineStart(uint64_t started_ms, uint64_t now_ms)
{
    return started_ms == 0u ? now_ms : started_ms;
}

bool udsRelayV3DeadlineExpired(uint64_t started_ms, uint64_t now_ms)
{
    return now_ms >= started_ms && now_ms - started_ms >= 20000u;
}

bool udsRelayV3PrejoinAdvertMatches(uint8_t flags, const uint8_t *body,
                                    uint16_t body_length,
                                    const uint8_t selected_room[16])
{
    return selected_room != NULL && body_length > 32u &&
           udsRelayV3BodyValidate(UDS_RELAY_V3_PKT_UDS_DATA, flags, body,
                                  body_length) &&
           memcmp(body, selected_room, 16u) == 0 &&
           readLe16(body + 16u) == 1u && readLe16(body + 18u) == 0xFFFFu &&
           body[20] == 1u && readLe32(body + 28u) == 1u && body[32] == 0x01u;
}

bool udsRelayV3PeersApply(UdsRelayV3Peers *peers, const uint8_t *body,
                          uint16_t body_length,
                          const uint8_t expected_room[16],
                          const uint8_t expected_scope[16],
                          const uint8_t expected_own_node_info[0x28],
                          uint8_t max_nodes,
                          uint16_t *out_changed)
{
    UdsRelayV3Peers next;
    uint16_t changed;
    if (peers == NULL || expected_room == NULL || expected_scope == NULL ||
        expected_own_node_info == NULL || out_changed == NULL ||
        max_nodes < 2u || max_nodes > 16u ||
        !udsRelayV3BodyValidate(UDS_RELAY_V3_PKT_PEER_MAP, 0u, body,
                                body_length) ||
        memcmp(body, expected_room, 16u) != 0 ||
        memcmp(body + 16u, expected_scope, 16u) != 0 ||
        readLe16(body + 32u) > max_nodes || body[34] > max_nodes)
        return false;

    memset(&next, 0, sizeof(next));
    memcpy(next.room_id, body, 16u);
    memcpy(next.scope, body + 16u, 16u);
    next.local_node = readLe16(body + 32u);
    next.roster_version = readLe32(body + 36u);
    for (uint8_t i = 0u; i < body[34]; i++)
    {
        const uint8_t *item = body + 40u + (size_t)i * 48u;
        uint16_t node = readLe16(item);
        uint32_t generation = readLe32(item + 4u);
        if (node > max_nodes || (node == 1u && generation != 1u) ||
            readLe16(item + 8u + 0x20u) != node)
            return false;
        next.valid_mask |= (uint16_t)(1u << (node - 1u));
        next.node_generations[node - 1u] = generation;
        memcpy(next.node_info[node - 1u], item + 8u, 0x28u);
    }
    if ((next.valid_mask & 1u) == 0u ||
        (next.valid_mask & (uint16_t)(1u << (next.local_node - 1u))) == 0u)
        return false;
    const uint8_t *own = next.node_info[next.local_node - 1u];
    if (memcmp(own, expected_own_node_info, 0x20u) != 0 ||
        memcmp(own + 0x22u, expected_own_node_info + 0x22u, 6u) != 0)
        return false;
    if (peers->roster_version != 0u)
    {
        if (next.roster_version < peers->roster_version)
            return false;
        if (next.roster_version == peers->roster_version)
        {
            if (memcmp(peers, &next, sizeof(next)) != 0)
                return false;
            *out_changed = 0u;
            return true;
        }
    }

    changed = (uint16_t)(peers->valid_mask ^ next.valid_mask);
    for (uint8_t node = 0u; node < 16u; node++)
    {
        uint16_t bit = (uint16_t)(1u << node);
        if ((peers->valid_mask & next.valid_mask & bit) != 0u &&
            (peers->node_generations[node] != next.node_generations[node] ||
             memcmp(peers->node_info[node], next.node_info[node], 0x28u) != 0))
            changed |= bit;
    }
    *peers = next;
    *out_changed = changed;
    return true;
}

bool udsRelayV3MessageEncode(uint8_t packet_type, uint8_t flags,
                             const uint8_t token[16], const uint8_t *body,
                             uint16_t body_length, uint32_t fragment_id,
                             uint8_t out_packets[2][UDS_RELAY_V3_MAX_DATAGRAM],
                             uint16_t out_lengths[2], uint8_t *out_count)
{
    UdsRelayV3Header header;
    uint8_t count;
    if (token == NULL || body == NULL || out_packets == NULL ||
        out_lengths == NULL || out_count == NULL ||
        body_length > UDS_RELAY_V3_MAX_LOGICAL_BODY ||
        !udsRelayV3BodyValidate(packet_type, flags, body, body_length))
        return false;
    count = body_length > UDS_RELAY_V3_MAX_FRAGMENT_BODY ? 2u : 1u;
    if (count == 2u && fragment_id == 0u)
        return false;
    memset(&header, 0, sizeof(header));
    header.packet_type = packet_type;
    header.flags = flags;
    memcpy(header.token, token, 16u);
    header.fragment_id = count == 1u ? 0u : fragment_id;
    header.fragment_count = count;
    header.logical_body_length = body_length;
    for (uint8_t i = 0u; i < count; i++)
    {
        size_t offset = (size_t)i * UDS_RELAY_V3_MAX_FRAGMENT_BODY;
        size_t length = body_length - offset;
        if (length > UDS_RELAY_V3_MAX_FRAGMENT_BODY)
            length = UDS_RELAY_V3_MAX_FRAGMENT_BODY;
        header.fragment_index = i;
        if (!udsRelayV3HeaderEncode(out_packets[i], UDS_RELAY_V3_MAX_DATAGRAM,
                                    &header))
            return false;
        memcpy(out_packets[i] + UDS_RELAY_V3_HEADER_SIZE, body + offset, length);
        out_lengths[i] = (uint16_t)(UDS_RELAY_V3_HEADER_SIZE + length);
    }
    if (count == 1u)
        out_lengths[1] = 0u;
    *out_count = count;
    return true;
}
