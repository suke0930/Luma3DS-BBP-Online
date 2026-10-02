/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "bbp_secure_transport.h"

#include "monocypher.h"

#include <limits.h>
#include <string.h>

#define V4_COMMON_SIZE 8u
#define V4_DATA_HEADER_SIZE 24u
#define V4_TAG_SIZE 16u
#define V4_CLIENT_HELLO 1u
#define V4_COOKIE 2u
#define V4_CLIENT_RETRY 3u
#define V4_SERVER_HELLO 4u
#define V4_DATA 5u
#define V4_ERROR 6u
#define V4_PHASE_NEW 0u
#define V4_PHASE_HELLO 1u
#define V4_PHASE_RETRY 2u
#define V4_PHASE_READY 3u

static const uint8_t protocol_name[] =
    "Noise_NN_25519_ChaChaPoly_BLAKE2b";

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

static void commonWrite(uint8_t out[V4_COMMON_SIZE], uint8_t type)
{
    writeLe32(out, UDS_RELAY_V4_MAGIC);
    writeLe16(out + 4u, UDS_RELAY_V4_VERSION);
    out[6] = type;
    out[7] = 0u;
}

static bool commonValid(const uint8_t *packet, size_t length, uint8_t type)
{
    return packet != NULL && length >= V4_COMMON_SIZE &&
           readLe32(packet) == UDS_RELAY_V4_MAGIC &&
           readLe16(packet + 4u) == UDS_RELAY_V4_VERSION &&
           packet[6] == type && packet[7] == 0u;
}

static bool nonzero(const uint8_t *data, size_t length)
{
    uint8_t value = 0u;
    for (size_t i = 0u; i < length; i++) value |= data[i];
    return value != 0u;
}

static void hashTwo(uint8_t out[64], const uint8_t *a, size_t a_length,
                    const uint8_t *b, size_t b_length)
{
    crypto_blake2b_ctx context;
    crypto_blake2b_init(&context, 64u);
    crypto_blake2b_update(&context, a, a_length);
    crypto_blake2b_update(&context, b, b_length);
    crypto_blake2b_final(&context, out);
    crypto_wipe(&context, sizeof(context));
}

static void hmacTwo(uint8_t out[64], const uint8_t *key, size_t key_length,
                    const uint8_t *a, size_t a_length,
                    const uint8_t *b, size_t b_length)
{
    uint8_t block[128] = {0};
    uint8_t inner[64];
    uint8_t outer[128];
    crypto_blake2b_ctx context;
    if (key_length > sizeof(block))
        crypto_blake2b(block, 64u, key, key_length);
    else if (key_length != 0u)
        memcpy(block, key, key_length);
    for (size_t i = 0u; i < sizeof(block); i++)
    {
        outer[i] = (uint8_t)(block[i] ^ 0x5Cu);
        block[i] ^= 0x36u;
    }
    crypto_blake2b_init(&context, 64u);
    crypto_blake2b_update(&context, block, sizeof(block));
    crypto_blake2b_update(&context, a, a_length);
    crypto_blake2b_update(&context, b, b_length);
    crypto_blake2b_final(&context, inner);
    crypto_blake2b_init(&context, 64u);
    crypto_blake2b_update(&context, outer, sizeof(outer));
    crypto_blake2b_update(&context, inner, sizeof(inner));
    crypto_blake2b_final(&context, out);
    crypto_wipe(&context, sizeof(context));
    crypto_wipe(block, sizeof(block));
    crypto_wipe(inner, sizeof(inner));
    crypto_wipe(outer, sizeof(outer));
}

static void hkdfTwo(uint8_t first[64], uint8_t second[64],
                    const uint8_t chaining_key[64],
                    const uint8_t *input, size_t input_length)
{
    uint8_t temporary[64];
    const uint8_t one = 1u, two = 2u;
    hmacTwo(temporary, chaining_key, 64u, input, input_length, NULL, 0u);
    hmacTwo(first, temporary, 64u, &one, 1u, NULL, 0u);
    hmacTwo(second, temporary, 64u, first, 64u, &two, 1u);
    crypto_wipe(temporary, sizeof(temporary));
}

static void initialState(uint8_t chaining_key[64], uint8_t handshake_hash[64],
                         const uint8_t client_public[32])
{
    memset(chaining_key, 0, 64u);
    memcpy(chaining_key, protocol_name, sizeof(protocol_name) - 1u);
    hashTwo(handshake_hash, chaining_key, 64u, client_public, 32u);
}

static void nonceWrite(uint8_t nonce[12], uint64_t packet_number)
{
    memset(nonce, 0, 4u);
    writeLe64(nonce + 4u, packet_number);
}

static bool aeadDecrypt(uint8_t *plaintext, const uint8_t *ciphertext,
                        size_t length, const uint8_t tag[16],
                        const uint8_t key[32], uint64_t packet_number,
                        const uint8_t *ad, size_t ad_length)
{
    uint8_t nonce[12];
    crypto_aead_ctx context;
    nonceWrite(nonce, packet_number);
    crypto_aead_init_ietf(&context, key, nonce);
    int mismatch = crypto_aead_read(&context, plaintext, tag, ad, ad_length,
                                    ciphertext, length);
    crypto_wipe(&context, sizeof(context));
    crypto_wipe(nonce, sizeof(nonce));
    return mismatch == 0;
}

static void aeadEncrypt(uint8_t *ciphertext, uint8_t tag[16],
                        const uint8_t *plaintext, size_t length,
                        const uint8_t key[32], uint64_t packet_number,
                        const uint8_t *ad, size_t ad_length)
{
    uint8_t nonce[12];
    crypto_aead_ctx context;
    nonceWrite(nonce, packet_number);
    crypto_aead_init_ietf(&context, key, nonce);
    crypto_aead_write(&context, ciphertext, tag, ad, ad_length,
                      plaintext, length);
    crypto_wipe(&context, sizeof(context));
    crypto_wipe(nonce, sizeof(nonce));
}

static bool replayAllows(const UdsRelayV4Client *state, uint64_t number)
{
    if (!state->receive_started || number > state->receive_maximum) return true;
    uint64_t distance = state->receive_maximum - number;
    return distance < 64u && (state->receive_mask & (UINT64_C(1) << distance)) == 0u;
}

static void replayMark(UdsRelayV4Client *state, uint64_t number)
{
    if (!state->receive_started)
    {
        state->receive_started = true;
        state->receive_maximum = number;
        state->receive_mask = 1u;
    }
    else if (number > state->receive_maximum)
    {
        uint64_t distance = number - state->receive_maximum;
        state->receive_mask = distance >= 64u ? 1u :
            (state->receive_mask << distance) | 1u;
        state->receive_maximum = number;
    }
    else
        state->receive_mask |= UINT64_C(1) << (state->receive_maximum - number);
}

size_t udsRelayV4ClientSize(void)
{
    return sizeof(UdsRelayV4Client);
}

bool udsRelayV4ClientInit(UdsRelayV4Client *state,
                          const uint8_t private_key[32])
{
    if (state == NULL || private_key == NULL || !nonzero(private_key, 32u))
        return false;
    memset(state, 0, sizeof(*state));
    memcpy(state->private_key, private_key, 32u);
    crypto_x25519_public_key(state->public_key, state->private_key);
    return true;
}

bool udsRelayV4ClientReady(const UdsRelayV4Client *state)
{
    return state != NULL && state->phase == V4_PHASE_READY;
}

uint32_t udsRelayV4ClientLastError(const UdsRelayV4Client *state)
{
    return state == NULL ? 0u : state->last_error;
}

bool udsRelayV4ClientHello(UdsRelayV4Client *state, uint8_t *out,
                           size_t out_capacity, size_t *out_length)
{
    if (out_length != NULL) *out_length = 0u;
    if (state == NULL || out == NULL || out_length == NULL || out_capacity < 40u ||
        state->phase == V4_PHASE_READY)
        return false;
    commonWrite(out, V4_CLIENT_HELLO);
    memcpy(out + V4_COMMON_SIZE, state->public_key, 32u);
    state->phase = V4_PHASE_HELLO;
    *out_length = 40u;
    return true;
}

bool udsRelayV4ClientHandshake(UdsRelayV4Client *state,
                               const uint8_t *packet, size_t packet_length,
                               uint8_t *out, size_t out_capacity,
                               size_t *out_length)
{
    if (out_length != NULL) *out_length = 0u;
    if (state == NULL || packet == NULL || out_length == NULL) return false;
    if (commonValid(packet, packet_length, V4_COOKIE) && packet_length == 32u &&
        (state->phase == V4_PHASE_HELLO || state->phase == V4_PHASE_RETRY))
    {
        if (out == NULL || out_capacity < 64u) return false;
        commonWrite(out, V4_CLIENT_RETRY);
        memcpy(out + 8u, state->public_key, 32u);
        memcpy(out + 40u, packet + 8u, 24u);
        state->phase = V4_PHASE_RETRY;
        *out_length = 64u;
        return true;
    }
    if (commonValid(packet, packet_length, V4_ERROR) && packet_length == 12u &&
        state->phase == V4_PHASE_RETRY)
    {
        uint32_t code = readLe32(packet + V4_COMMON_SIZE);
        if (code != UDS_RELAY_V4_ERROR_SERVER_BUSY &&
            code != UDS_RELAY_V4_ERROR_SOURCE_LIMIT)
            return false;
        state->last_error = code;
        return true;
    }
    if (!commonValid(packet, packet_length, V4_SERVER_HELLO) ||
        packet_length != 64u || state->phase != V4_PHASE_RETRY)
        return false;

    uint8_t chaining_key[64], handshake_hash[64], shared[32];
    uint8_t new_chaining_key[64], handshake_key[64], split_first[64], split_second[64];
    uint8_t connection_id[8], zero[32] = {0};
    bool valid = false;
    initialState(chaining_key, handshake_hash, state->public_key);
    hashTwo(handshake_hash, handshake_hash, 64u, packet + 8u, 32u);
    crypto_x25519(shared, state->private_key, packet + 8u);
    if (crypto_verify32(shared, zero) == 0) goto cleanup;
    hkdfTwo(new_chaining_key, handshake_key, chaining_key, shared, 32u);
    if (!aeadDecrypt(connection_id, packet + 40u, 8u, packet + 48u,
                     handshake_key, 0u, handshake_hash, 64u) ||
        readLe64(connection_id) == 0u)
        goto cleanup;
    hashTwo(handshake_hash, handshake_hash, 64u, packet + 40u, 24u);
    hkdfTwo(split_first, split_second, new_chaining_key, NULL, 0u);
    memcpy(state->send_key, split_first, 32u);
    memcpy(state->receive_key, split_second, 32u);
    state->connection_id = readLe64(connection_id);
    state->send_number = 0u;
    state->receive_maximum = 0u;
    state->receive_mask = 0u;
    state->receive_started = false;
    state->phase = V4_PHASE_READY;
    valid = true;
cleanup:
    crypto_wipe(chaining_key, sizeof(chaining_key));
    crypto_wipe(handshake_hash, sizeof(handshake_hash));
    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(new_chaining_key, sizeof(new_chaining_key));
    crypto_wipe(handshake_key, sizeof(handshake_key));
    crypto_wipe(split_first, sizeof(split_first));
    crypto_wipe(split_second, sizeof(split_second));
    crypto_wipe(connection_id, sizeof(connection_id));
    return valid;
}

bool udsRelayV4ClientEncrypt(UdsRelayV4Client *state,
                             const uint8_t *plaintext, size_t plaintext_length,
                             uint8_t *out, size_t out_capacity,
                             size_t *out_length)
{
    if (out_length != NULL) *out_length = 0u;
    if (!udsRelayV4ClientReady(state) || plaintext == NULL ||
        plaintext_length == 0u || plaintext_length > UDS_RELAY_V4_MAX_INNER ||
        out == NULL || out_length == NULL ||
        out_capacity < V4_DATA_HEADER_SIZE + plaintext_length + V4_TAG_SIZE ||
        state->send_number == UINT64_MAX)
        return false;
    commonWrite(out, V4_DATA);
    writeLe64(out + 8u, state->connection_id);
    writeLe64(out + 16u, state->send_number);
    aeadEncrypt(out + 24u, out + 24u + plaintext_length, plaintext,
                plaintext_length, state->send_key, state->send_number,
                out, V4_DATA_HEADER_SIZE);
    state->send_number++;
    *out_length = V4_DATA_HEADER_SIZE + plaintext_length + V4_TAG_SIZE;
    return true;
}

bool udsRelayV4ClientDecrypt(UdsRelayV4Client *state,
                             const uint8_t *packet, size_t packet_length,
                             uint8_t *out, size_t out_capacity,
                             size_t *out_length)
{
    if (out_length != NULL) *out_length = 0u;
    if (!udsRelayV4ClientReady(state) ||
        !commonValid(packet, packet_length, V4_DATA) ||
        packet_length <= V4_DATA_HEADER_SIZE + V4_TAG_SIZE ||
        packet_length > UDS_RELAY_V4_MAX_DATAGRAM || out == NULL ||
        out_length == NULL || readLe64(packet + 8u) != state->connection_id)
        return false;
    size_t plaintext_length = packet_length - V4_DATA_HEADER_SIZE - V4_TAG_SIZE;
    uint64_t packet_number = readLe64(packet + 16u);
    if (plaintext_length > UDS_RELAY_V4_MAX_INNER ||
        out_capacity < plaintext_length || !replayAllows(state, packet_number) ||
        !aeadDecrypt(out, packet + 24u, plaintext_length,
                     packet + 24u + plaintext_length, state->receive_key,
                     packet_number, packet, V4_DATA_HEADER_SIZE))
        return false;
    replayMark(state, packet_number);
    *out_length = plaintext_length;
    return true;
}

void udsRelayV4ClientClear(UdsRelayV4Client *state)
{
    if (state != NULL) crypto_wipe(state, sizeof(*state));
}
