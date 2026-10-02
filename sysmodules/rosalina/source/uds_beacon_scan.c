/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "uds_beacon_scan.h"

#include <string.h>

enum {
    UDS_BEACON_FIXED_HEADER_LEN = 12,
    UDS_BEACON_VENDOR_ELEMENT = 0xDD,
    UDS_BEACON_NINTENDO_OUI_LEN = 3,
    UDS_BEACON_TYPE_OFFSET = 3,
    UDS_BEACON_TYPE21 = 21,
    UDS_BEACON_TYPE24 = 24,
    UDS_BEACON_TYPE25 = 25,
    UDS_BEACON_TYPE21_MIN_LEN = 0x34,
    UDS_BEACON_TYPE21_MAX_LEN = 0xFC,
    UDS_BEACON_TYPE24_MIN_LEN = 0x12,
    UDS_BEACON_TYPE24_MAX_LEN = 0xFE,
    UDS_BEACON_TYPE25_MAX_LEN = 0xFE,
    UDS_BEACON_TYPE21_APPDATA_OFFSET = 0x33,
    UDS_BEACON_TYPE21_APPDATA_MAX_LEN = 0xC8,
    UDS_BEACON_NETWORK_INFO_SIZE = 0x108,
    UDS_BEACON_NODE_INFO_SIZE = 0x28,
    UDS_BEACON_SESSION_CREATE_SIZE = UDS_BEACON_NETWORK_INFO_SIZE +
                                     UDS_BEACON_NODE_INFO_SIZE,
};

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint16_t read_le16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t rotate_left(uint32_t value, unsigned bits)
{
    return (value << bits) | (value >> (32u - bits));
}

static void sha1(const uint8_t *data, size_t len, uint8_t digest[20])
{
    uint8_t padded[320];
    uint32_t state[5] = {
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u,
    };
    size_t padded_len = (len + 9u + 63u) & ~(size_t)63u;
    uint64_t bit_len = (uint64_t)len * 8u;

    memset(padded, 0, padded_len);
    memcpy(padded, data, len);
    padded[len] = 0x80u;
    for (size_t i = 0; i < 8u; ++i)
        padded[padded_len - 1u - i] = (uint8_t)(bit_len >> (i * 8u));

    for (size_t block = 0; block < padded_len; block += 64u) {
        uint32_t words[80];
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];

        for (size_t i = 0; i < 16u; ++i)
            words[i] = read_be32(padded + block + i * 4u);
        for (size_t i = 16u; i < 80u; ++i)
            words[i] = rotate_left(words[i - 3u] ^ words[i - 8u] ^
                                   words[i - 14u] ^ words[i - 16u], 1u);

        for (size_t i = 0; i < 80u; ++i) {
            uint32_t function;
            uint32_t constant;
            uint32_t next;

            if (i < 20u) {
                function = (b & c) | (~b & d);
                constant = 0x5A827999u;
            } else if (i < 40u) {
                function = b ^ c ^ d;
                constant = 0x6ED9EBA1u;
            } else if (i < 60u) {
                function = (b & c) | (b & d) | (c & d);
                constant = 0x8F1BBCDCu;
            } else {
                function = b ^ c ^ d;
                constant = 0xCA62C1D6u;
            }
            next = rotate_left(a, 5u) + function + e + constant + words[i];
            e = d;
            d = c;
            c = rotate_left(b, 30u);
            b = a;
            a = next;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

    for (size_t i = 0; i < 5u; ++i) {
        digest[i * 4u] = (uint8_t)(state[i] >> 24);
        digest[i * 4u + 1u] = (uint8_t)(state[i] >> 16);
        digest[i * 4u + 2u] = (uint8_t)(state[i] >> 8);
        digest[i * 4u + 3u] = (uint8_t)state[i];
    }
}

static bool is_valid_unicast_mac(const uint8_t *mac)
{
    bool nonzero = false;

    if (mac == NULL || (mac[0] & 1u) != 0u)
        return false;
    for (size_t i = 0; i < 6u; ++i)
        nonzero |= mac[i] != 0u;
    return nonzero;
}

typedef struct {
    const uint8_t *type21_body;
    size_t type21_len;
    const uint8_t *type24_body;
    size_t type24_len;
    const uint8_t *type25_body;
    size_t type25_len;
} TypeElements;

static bool parse_type_elements(const uint8_t *frame, size_t frame_len,
                                TypeElements *out)
{
    TypeElements found = { 0 };
    size_t offset;

    if (frame == NULL || out == NULL ||
        frame_len < UDS_BEACON_FIXED_HEADER_LEN)
        return false;

    offset = UDS_BEACON_FIXED_HEADER_LEN;
    while (offset < frame_len) {
        uint8_t element_id;
        uint8_t element_len;
        const uint8_t *body;

        if (frame_len - offset < 2u)
            return false;

        element_id = frame[offset];
        element_len = frame[offset + 1u];
        offset += 2u;
        if ((size_t)element_len > frame_len - offset)
            return false;

        body = frame + offset;
        if (element_id == UDS_BEACON_VENDOR_ELEMENT) {
            if (element_len < UDS_BEACON_NINTENDO_OUI_LEN + 1u)
                return false;

            if (memcmp(body, "\x00\x1f\x32", UDS_BEACON_NINTENDO_OUI_LEN) == 0) {
                switch (body[UDS_BEACON_TYPE_OFFSET]) {
                case UDS_BEACON_TYPE21:
                    found.type21_body = body;
                    found.type21_len = element_len;
                    break;
                case UDS_BEACON_TYPE24:
                    found.type24_body = body;
                    found.type24_len = element_len;
                    break;
                case UDS_BEACON_TYPE25:
                    found.type25_body = body;
                    found.type25_len = element_len;
                    break;
                default:
                    break;
                }
            }
        }
        offset += element_len;
    }

    if (found.type21_body == NULL ||
        found.type21_len < UDS_BEACON_TYPE21_MIN_LEN ||
        found.type21_len > UDS_BEACON_TYPE21_MAX_LEN ||
        found.type24_body == NULL ||
        found.type24_len < UDS_BEACON_TYPE24_MIN_LEN ||
        found.type24_len > UDS_BEACON_TYPE24_MAX_LEN ||
        (found.type25_body != NULL && found.type25_len > UDS_BEACON_TYPE25_MAX_LEN))
        return false;

    if (found.type21_body[UDS_BEACON_TYPE21_APPDATA_OFFSET] >
            UDS_BEACON_TYPE21_APPDATA_MAX_LEN ||
        found.type21_body[UDS_BEACON_TYPE21_APPDATA_OFFSET] >
            found.type21_len - UDS_BEACON_TYPE21_MIN_LEN)
        return false;

    *out = found;
    return true;
}

bool udsBeaconExtractType21Identity(const uint8_t *frame, size_t frame_len,
                                    UdsBeaconType21Identity *out)
{
    TypeElements elements;

    if (out == NULL || !parse_type_elements(frame, frame_len, &elements))
        return false;

    out->wlan_comm_id = read_be32(elements.type21_body + 4u);
    out->id8 = elements.type21_body[8u];
    out->network_id = read_be32(elements.type21_body + 0x0Cu);
    out->max_nodes = elements.type21_body[0x11u];
    return true;
}

bool udsBeaconMatchesScanQuery(const uint8_t *frame, size_t frame_len,
                               uint32_t wlan_comm_id, uint8_t id8)
{
    UdsBeaconType21Identity identity;
    return udsBeaconExtractType21Identity(frame, frame_len, &identity) &&
           udsBeaconScanQueryMatchesIdentity(wlan_comm_id, id8, &identity);
}

bool udsBeaconScanQueryMatchesIdentity(uint32_t wlan_comm_id, uint8_t id8,
                                       const UdsBeaconType21Identity *identity)
{
    return identity != NULL && identity->wlan_comm_id == wlan_comm_id &&
           identity->id8 == id8;
}

bool udsBeaconAdvanceCandidateGeneration(uint32_t current_generation,
                                         bool current_valid,
                                         bool key_changed,
                                         uint32_t *out_generation)
{
    if (out_generation == NULL)
        return false;

    *out_generation = current_generation;
    if (!key_changed)
        return current_valid && current_generation != 0u;

    if (!current_valid)
    {
        *out_generation = 1u;
        return true;
    }

    if (current_generation == UINT32_MAX)
        return false;

    *out_generation = current_generation + 1u;
    return true;
}

bool udsBeaconCandidateMatchesCmd1E(const uint8_t *input, size_t input_len,
                                    const UdsBeaconCandidateIdentity *candidate)
{
    if (input == NULL || candidate == NULL || input_len != 0x108u ||
        candidate->initialized == 0u)
        return false;

    return memcmp(input + 0x00u, candidate->host_mac, 6u) == 0 &&
           input[0x06u] == (uint8_t)candidate->channel &&
           input[0x08u] == candidate->initialized &&
           read_be32(input + 0x10u) == candidate->wlan_comm_id &&
           input[0x14u] == candidate->id8 &&
           read_be32(input + 0x18u) == candidate->network_id &&
           input[0x1Du] == candidate->max_nodes;
}

bool udsBeaconBuildSemanticFrame(const uint8_t *descriptor,
                                 size_t descriptor_len, uint8_t *out_frame,
                                 size_t out_capacity, size_t *out_len,
                                 UdsBeaconCandidateIdentity *out_identity)
{
    const uint8_t *network;
    const uint8_t *node;
    UdsBeaconCandidateIdentity identity;
    size_t type21_len;
    size_t frame_len;
    size_t offset;
    uint8_t *type21_body;
    uint8_t app_len;

    if (out_len != NULL)
        *out_len = 0u;
    if (descriptor == NULL || descriptor_len != UDS_BEACON_SESSION_CREATE_SIZE ||
        out_frame == NULL || out_len == NULL || out_identity == NULL)
        return false;

    network = descriptor;
    node = descriptor + UDS_BEACON_NETWORK_INFO_SIZE;
    app_len = network[0x3Fu];
    if (!is_valid_unicast_mac(network) || network[6] == 0u ||
        network[8] != 1u || memcmp(network + 0x0Cu, "\x00\x1f\x32\x15", 4u) != 0 ||
        network[0x1Cu] != 1u || network[0x1Du] < 2u ||
        network[0x1Du] > 16u || app_len > UDS_BEACON_TYPE21_APPDATA_MAX_LEN ||
        read_le16(node + 0x20u) != 1u)
        return false;

    type21_len = UDS_BEACON_TYPE21_MIN_LEN + app_len;
    frame_len = UDS_BEACON_FIXED_HEADER_LEN + 2u + type21_len + 2u +
                UDS_BEACON_TYPE24_MIN_LEN;
    if (frame_len > out_capacity)
        return false;

    memset(out_frame, 0, frame_len);
    offset = UDS_BEACON_FIXED_HEADER_LEN;
    out_frame[offset++] = UDS_BEACON_VENDOR_ELEMENT;
    out_frame[offset++] = (uint8_t)type21_len;
    type21_body = out_frame + offset;
    memcpy(out_frame + offset, network + 0x0Cu, 0x1Fu);
    offset += 0x1Fu;
    offset += 20u;
    out_frame[offset++] = app_len;
    memcpy(out_frame + offset, network + 0x40u, app_len);
    offset += app_len;
    sha1(type21_body, type21_len, type21_body + 0x1Fu);

    out_frame[offset++] = UDS_BEACON_VENDOR_ELEMENT;
    out_frame[offset++] = UDS_BEACON_TYPE24_MIN_LEN;
    memcpy(out_frame + offset, "\x00\x1f\x32\x18", 4u);
    offset += 4u + 14u;

    memset(&identity, 0, sizeof(identity));
    memcpy(identity.host_mac, network, sizeof(identity.host_mac));
    identity.channel = network[6];
    identity.initialized = 1u;
    identity.wlan_comm_id = read_be32(network + 0x10u);
    identity.id8 = network[0x14u];
    identity.network_id = read_be32(network + 0x18u);
    identity.max_nodes = network[0x1Du];
    *out_len = offset;
    *out_identity = identity;
    return true;
}
