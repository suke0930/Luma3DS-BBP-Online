/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "uds_dlp_advert.h"

#include <string.h>

const uint8_t udsDlpAdvertModIv[16] = {
    0xFE, 0x44, 0x9A, 0xC1, 0x3A, 0xE3, 0xB4, 0x09,
    0x50, 0x11, 0xD1, 0x89, 0x44, 0x10, 0x78, 0x33,
};

UdsDlpAdvertRoute udsDlpAdvertDiscoveryRoute(bool has_selected_membership,
                                             bool selected_spectator,
                                             bool current_host_token)
{
    if (has_selected_membership && !selected_spectator)
        return UDS_DLP_ADVERT_ROUTE_FALLTHROUGH;
    if (!current_host_token)
        return UDS_DLP_ADVERT_ROUTE_CONSUME_DROP;
    return selected_spectator ? UDS_DLP_ADVERT_ROUTE_CONSUME_ACCEPT
                              : UDS_DLP_ADVERT_ROUTE_CONSUME_PROVISIONAL;
}

bool udsDlpAdvertShouldPrime(bool cache_complete, size_t available_slots,
                             bool already_primed)
{
    return cache_complete && !already_primed &&
           available_slots >= UDS_DLP_ADVERT_FRAGMENT_COUNT;
}

static uint32_t read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t read_u32_be_zeroed_checksum(const uint8_t *p, size_t offset)
{
    uint32_t word = 0;
    for (size_t i = 0; i < 4u; ++i)
    {
        size_t byte_offset = offset + i;
        uint8_t byte = (byte_offset >= 8u && byte_offset < 12u) ? 0u : p[byte_offset];
        word = (word << 8) | byte;
    }
    return word;
}

static uint32_t read_trailing_be_zeroed_checksum(const uint8_t *p,
                                                 size_t offset, size_t count)
{
    uint32_t word = 0;
    for (size_t i = 0; i < count; ++i)
    {
        size_t byte_offset = offset + i;
        uint8_t byte = (byte_offset >= 8u && byte_offset < 12u) ? 0u : p[byte_offset];
        word = (word << 8) | byte;
    }
    return word << (unsigned)(8u * (4u - count));
}

uint16_t udsDlpAdvertExpectedLength(uint8_t index)
{
    static const uint16_t lengths[UDS_DLP_ADVERT_FRAGMENT_COUNT] = {
        0x0300u, 0x05A8u, 0x05A8u, 0x05A8u, 0x05B8u,
    };
    return index < UDS_DLP_ADVERT_FRAGMENT_COUNT ? lengths[index] : 0u;
}

uint32_t udsDlpAdvertChecksum(const uint8_t *packet, size_t packet_length,
                              uint32_t aes_value)
{
    uint32_t working_hash = 0u;
    size_t aligned_length;
    uint8_t seed_bytes[4];
    uint8_t rounds;
    uint8_t shift;
    uint32_t aes_swap;

    if (packet == NULL || packet_length < 12u)
        return 0u;

    aligned_length = packet_length & ~(size_t)3u;
    for (size_t offset = 0; offset < aligned_length; offset += 4u)
        working_hash += read_u32_be_zeroed_checksum(packet, offset);

    if (aligned_length != packet_length)
        working_hash += read_trailing_be_zeroed_checksum(
            packet, aligned_length, packet_length - aligned_length);

    seed_bytes[0] = (uint8_t)aes_value;
    seed_bytes[1] = (uint8_t)(aes_value >> 8);
    seed_bytes[2] = (uint8_t)(aes_value >> 16);
    seed_bytes[3] = (uint8_t)(aes_value >> 24);
    rounds = (uint8_t)((seed_bytes[3] & 7u) + 2u);
    shift = (uint8_t)((seed_bytes[2] & 0x0Fu) + 4u);
    aes_swap = ((uint32_t)seed_bytes[0] << 24) |
               ((uint32_t)seed_bytes[1] << 16) |
               ((uint32_t)seed_bytes[2] << 8) |
               (uint32_t)seed_bytes[3];
    for (uint8_t i = 0; i < rounds; ++i)
    {
        /* Native checksum uses this asymmetric shift-or, not a rotation. */
        working_hash = ((working_hash >> shift) |
                        (working_hash << shift)) ^ aes_swap;
    }
    return ((working_hash & 0x000000FFu) << 24) |
           ((working_hash & 0x0000FF00u) << 8) |
           ((working_hash & 0x00FF0000u) >> 8) |
           ((working_hash & 0xFF000000u) >> 24);
}

bool udsDlpAdvertChecksumValid(const uint8_t *packet, size_t packet_length,
                               uint32_t aes_value)
{
    if (packet == NULL || packet_length < 12u)
        return false;
    return read_u32_le(packet + 8u) ==
           udsDlpAdvertChecksum(packet, packet_length, aes_value);
}

static bool validate_fragment_shape(const uint8_t *packet, size_t packet_length,
                                    uint8_t expected_index)
{
    uint16_t expected_length;

    if (packet == NULL || expected_index >= UDS_DLP_ADVERT_FRAGMENT_COUNT)
        return false;
    expected_length = udsDlpAdvertExpectedLength(expected_index);
    if (packet_length != expected_length || packet_length < 0x1Cu ||
        packet[0] != 0x01u ||
        (packet[1] != 0x00u && packet[1] != 0x02u) ||
        packet[2] != 0x00u || packet[3] != 0x00u ||
        ((uint16_t)packet[4] << 8 | packet[5]) != expected_length ||
        packet[6] != 0x02u || packet[7] != 0x00u ||
        packet[0x0Cu] != expected_index || packet[0x0Du] != 5u ||
        packet[0x0Eu] != 0u)
        return false;
    if (expected_index == 0u &&
        (memcmp(packet + 0x10u, "\x00\x04\x00\x01\x00\x0A\x0B\x01", 8u) != 0 ||
         packet[0x1Au] != 0x01u || packet[0x1Bu] != 0x00u))
        return false;
    return true;
}

bool udsDlpAdvertValidateFragment(const uint8_t *packet, size_t packet_length,
                                  uint8_t expected_index, uint32_t aes_value)
{
    return validate_fragment_shape(packet, packet_length, expected_index) &&
           udsDlpAdvertChecksumValid(packet, packet_length, aes_value);
}

bool udsDlpAdvertGenerateSeed(const uint8_t host_mac[6],
                              UdsDlpAdvertAesCtr4 aes, void *opaque,
                              uint32_t *out_seed)
{
    uint8_t ctr[16];
    uint8_t input[4] = {0, 0, 0, 0};
    uint8_t output[4] = {0, 0, 0, 0};
    uint32_t seed;

    if (host_mac == NULL || aes == NULL || out_seed == NULL)
        return false;
    *out_seed = 0u;
    for (size_t i = 0; i < sizeof(ctr); ++i)
        ctr[i] = (uint8_t)(host_mac[i % 6u] ^ udsDlpAdvertModIv[i]);
    if (!aes(opaque, 4u, input, output, 2u, 5u, ctr))
        return false;
    seed = read_u32_le(output);
    if (seed == 0u)
        return false;
    *out_seed = seed;
    return true;
}

void udsDlpAdvertCacheReset(UdsDlpAdvertCache *cache)
{
    if (cache != NULL)
        memset(cache, 0, sizeof(*cache));
}

static bool cache_fragment(UdsDlpAdvertCache *cache, const uint8_t *packet,
                           size_t packet_length, bool validated)
{
    uint8_t index = packet[0x0Cu];
    uint8_t bit;

    bit = (uint8_t)(1u << index);
    if ((cache->bitmap & bit) != 0u)
    {
        if (cache->lengths[index] == packet_length &&
            memcmp(cache->fragments[index], packet, packet_length) == 0)
        {
            if (validated)
                cache->validated_bitmap |= bit;
            return true;
        }
        cache->invalid = 1u;
        cache->bitmap = 0u;
        cache->validated_bitmap = 0u;
        cache->title_valid = 0u;
        return false;
    }
    memcpy(cache->fragments[index], packet, packet_length);
    cache->lengths[index] = (uint16_t)packet_length;
    cache->bitmap |= bit;
    if (validated)
        cache->validated_bitmap |= bit;
    if (index == 0u)
        cache->title_valid = 1u;
    return true;
}

bool udsDlpAdvertCacheAccept(UdsDlpAdvertCache *cache,
                             const uint8_t *packet, size_t packet_length,
                             uint32_t aes_value)
{
    uint8_t index;
    if (cache == NULL || packet == NULL || packet_length <= 0x0Cu || cache->invalid)
        return false;
    index = packet[0x0Cu];
    return udsDlpAdvertValidateFragment(packet, packet_length, index, aes_value) &&
           cache_fragment(cache, packet, packet_length, true);
}

bool udsDlpAdvertCacheAcceptProvisional(UdsDlpAdvertCache *cache,
                                        const uint8_t *packet,
                                        size_t packet_length)
{
    uint8_t index;
    if (cache == NULL || packet == NULL || packet_length <= 0x0Cu || cache->invalid)
        return false;
    index = packet[0x0Cu];
    return validate_fragment_shape(packet, packet_length, index) &&
           cache_fragment(cache, packet, packet_length, false);
}

bool udsDlpAdvertCacheValidate(UdsDlpAdvertCache *cache, uint32_t aes_value)
{
    if (cache == NULL || cache->invalid || !cache->title_valid || cache->bitmap != 0x1Fu)
        return false;
    for (uint8_t index = 0; index < UDS_DLP_ADVERT_FRAGMENT_COUNT; ++index)
    {
        if (!udsDlpAdvertValidateFragment(cache->fragments[index],
                                          cache->lengths[index], index, aes_value))
        {
            cache->invalid = 1u;
            cache->bitmap = 0u;
            cache->validated_bitmap = 0u;
            cache->title_valid = 0u;
            return false;
        }
    }
    cache->validated_bitmap = 0x1Fu;
    return true;
}

bool udsDlpAdvertCacheComplete(const UdsDlpAdvertCache *cache)
{
    return cache != NULL && !cache->invalid && cache->title_valid &&
           cache->bitmap == 0x1Fu && cache->validated_bitmap == 0x1Fu;
}

bool udsDlpAdvertCacheCopyComplete(const UdsDlpAdvertCache *cache,
                                   size_t available_slots,
                                   uint8_t out_fragments[UDS_DLP_ADVERT_FRAGMENT_COUNT]
                                                        [UDS_DLP_ADVERT_MAX_FRAGMENT_SIZE],
                                   uint16_t out_lengths[UDS_DLP_ADVERT_FRAGMENT_COUNT])
{
    if (!udsDlpAdvertCacheComplete(cache) || available_slots < UDS_DLP_ADVERT_FRAGMENT_COUNT ||
        out_fragments == NULL || out_lengths == NULL)
        return false;
    for (uint8_t i = 0; i < UDS_DLP_ADVERT_FRAGMENT_COUNT; ++i)
    {
        memcpy(out_fragments[i], cache->fragments[i], cache->lengths[i]);
        out_lengths[i] = cache->lengths[i];
    }
    return true;
}
