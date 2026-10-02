/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UDS_DLP_ADVERT_H
#define UDS_DLP_ADVERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDS_DLP_ADVERT_FRAGMENT_COUNT 5u
#define UDS_DLP_ADVERT_MAX_FRAGMENT_SIZE 0x5B8u

extern const uint8_t udsDlpAdvertModIv[16];

typedef bool (*UdsDlpAdvertAesCtr4)(void *opaque, uint32_t size,
                                    const uint8_t input[4], uint8_t output[4],
                                    uint32_t algorithm, uint32_t key_type,
                                    uint8_t ctr[16]);

typedef enum {
    UDS_DLP_ADVERT_ROUTE_FALLTHROUGH = 0,
    UDS_DLP_ADVERT_ROUTE_CONSUME_DROP = 1,
    UDS_DLP_ADVERT_ROUTE_CONSUME_ACCEPT = 2,
    UDS_DLP_ADVERT_ROUTE_CONSUME_PROVISIONAL = 3,
} UdsDlpAdvertRoute;

UdsDlpAdvertRoute udsDlpAdvertDiscoveryRoute(bool has_selected_membership,
                                             bool selected_spectator,
                                             bool current_host_token);

bool udsDlpAdvertShouldPrime(bool cache_complete, size_t available_slots,
                             bool already_primed);

uint16_t udsDlpAdvertExpectedLength(uint8_t index);

uint32_t udsDlpAdvertChecksum(const uint8_t *packet, size_t packet_length,
                              uint32_t aes_value);
bool udsDlpAdvertChecksumValid(const uint8_t *packet, size_t packet_length,
                               uint32_t aes_value);

bool udsDlpAdvertValidateFragment(const uint8_t *packet, size_t packet_length,
                                  uint8_t expected_index, uint32_t aes_value);

bool udsDlpAdvertGenerateSeed(const uint8_t host_mac[6],
                              UdsDlpAdvertAesCtr4 aes, void *opaque,
                              uint32_t *out_seed);

/* Candidate identity and role ownership remain with the caller. */
typedef struct {
    uint8_t fragments[UDS_DLP_ADVERT_FRAGMENT_COUNT]
                     [UDS_DLP_ADVERT_MAX_FRAGMENT_SIZE];
    uint16_t lengths[UDS_DLP_ADVERT_FRAGMENT_COUNT];
    uint8_t bitmap;
    uint8_t validated_bitmap;
    uint8_t invalid;
    uint8_t title_valid;
} UdsDlpAdvertCache;

void udsDlpAdvertCacheReset(UdsDlpAdvertCache *cache);
bool udsDlpAdvertCacheAccept(UdsDlpAdvertCache *cache,
                             const uint8_t *packet, size_t packet_length,
                             uint32_t aes_value);
bool udsDlpAdvertCacheAcceptProvisional(UdsDlpAdvertCache *cache,
                                        const uint8_t *packet,
                                        size_t packet_length);
bool udsDlpAdvertCacheValidate(UdsDlpAdvertCache *cache, uint32_t aes_value);
bool udsDlpAdvertCacheComplete(const UdsDlpAdvertCache *cache);
bool udsDlpAdvertCacheCopyComplete(const UdsDlpAdvertCache *cache,
                                   size_t available_slots,
                                   uint8_t out_fragments[UDS_DLP_ADVERT_FRAGMENT_COUNT]
                                                        [UDS_DLP_ADVERT_MAX_FRAGMENT_SIZE],
                                   uint16_t out_lengths[UDS_DLP_ADVERT_FRAGMENT_COUNT]);

#endif
