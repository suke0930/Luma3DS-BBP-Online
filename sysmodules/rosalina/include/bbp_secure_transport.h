/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BBP_SECURE_TRANSPORT_H
#define BBP_SECURE_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDS_RELAY_V4_MAGIC 0x50534455u
#define UDS_RELAY_V4_VERSION 4u
#define UDS_RELAY_V4_MAX_INNER 1200u
#define UDS_RELAY_V4_MAX_DATAGRAM 1240u
#define UDS_RELAY_V4_ERROR_SERVER_BUSY 1u
#define UDS_RELAY_V4_ERROR_SOURCE_LIMIT 2u

typedef struct UdsRelayV4Client {
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint8_t send_key[32];
    uint8_t receive_key[32];
    uint64_t connection_id;
    uint64_t send_number;
    uint64_t receive_maximum;
    uint64_t receive_mask;
    uint32_t last_error;
    uint8_t phase;
    bool receive_started;
} UdsRelayV4Client;

size_t udsRelayV4ClientSize(void);
bool udsRelayV4ClientInit(UdsRelayV4Client *state,
                          const uint8_t private_key[32]);
bool udsRelayV4ClientReady(const UdsRelayV4Client *state);
uint32_t udsRelayV4ClientLastError(const UdsRelayV4Client *state);
bool udsRelayV4ClientHello(UdsRelayV4Client *state, uint8_t *out,
                           size_t out_capacity, size_t *out_length);
bool udsRelayV4ClientHandshake(UdsRelayV4Client *state,
                               const uint8_t *packet, size_t packet_length,
                               uint8_t *out, size_t out_capacity,
                               size_t *out_length);
bool udsRelayV4ClientEncrypt(UdsRelayV4Client *state,
                             const uint8_t *plaintext, size_t plaintext_length,
                             uint8_t *out, size_t out_capacity,
                             size_t *out_length);
bool udsRelayV4ClientDecrypt(UdsRelayV4Client *state,
                             const uint8_t *packet, size_t packet_length,
                             uint8_t *out, size_t out_capacity,
                             size_t *out_length);
void udsRelayV4ClientClear(UdsRelayV4Client *state);

#endif
