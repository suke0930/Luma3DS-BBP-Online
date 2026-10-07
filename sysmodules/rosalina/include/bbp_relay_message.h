/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BBP_RELAY_MESSAGE_H
#define BBP_RELAY_MESSAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDS_RELAY_V3_MAGIC 0x50534455u
#define UDS_RELAY_V3_VERSION 3u
#define UDS_RELAY_V3_HEADER_SIZE 32u
#define UDS_RELAY_V3_MAX_DATAGRAM 1200u
#define UDS_RELAY_V3_MAX_FRAGMENT_BODY 1168u
#define UDS_RELAY_V3_MAX_LOGICAL_BODY 1510u
#define UDS_RELAY_V3_MAX_REASSEMBLIES 8u
#define UDS_RELAY_V3_ADMISSION_MARKER "BBP_PROXY_ACCESS"
#define UDS_RELAY_V3_STATUS_EXTENSION_VERSION 1u
#define UDS_RELAY_V3_STATUS_CAP_U16_COUNTS 1u

#define UDS_RELAY_V3_PKT_REGISTER 0x01u
#define UDS_RELAY_V3_PKT_REGISTER_ACK 0x02u
#define UDS_RELAY_V3_PKT_HEARTBEAT 0x03u
#define UDS_RELAY_V3_PKT_ROOM_CREATE 0x04u
#define UDS_RELAY_V3_PKT_ROOM_CREATED 0x05u
#define UDS_RELAY_V3_PKT_ROOM_LIST 0x06u
#define UDS_RELAY_V3_PKT_ROOM_CLOSE 0x07u
#define UDS_RELAY_V3_PKT_JOIN 0x08u
#define UDS_RELAY_V3_PKT_PEER_MAP 0x09u
#define UDS_RELAY_V3_PKT_UDS_DATA 0x0Au
#define UDS_RELAY_V3_PKT_LEAVE 0x0Bu
#define UDS_RELAY_V3_PKT_DISCONNECT 0x0Cu
#define UDS_RELAY_V3_PKT_ERROR 0x0Du
#define UDS_RELAY_V3_PKT_RETIRE_ACK 0x0Eu
#define UDS_RELAY_V3_PKT_PATH_CHALLENGE 0x0Fu
#define UDS_RELAY_V3_PKT_PATH_RESPONSE 0x10u
#define UDS_RELAY_V3_PKT_PROBE 0x11u
#define UDS_RELAY_V3_PKT_PROBE_ACK 0x12u
#define UDS_RELAY_V3_PKT_STATUS_QUERY 0x13u
#define UDS_RELAY_V3_PKT_STATUS_REPLY 0x14u
#define UDS_RELAY_V3_PKT_UNREGISTER 0x15u
#define UDS_RELAY_V3_FLAG_UNICAST 0x01u
#define UDS_RELAY_V3_FLAG_BROADCAST 0x02u

typedef struct {
    uint8_t packet_type;
    uint8_t flags;
    uint8_t token[16];
    uint32_t fragment_id;
    uint8_t fragment_index;
    uint8_t fragment_count;
    uint16_t logical_body_length;
} UdsRelayV3Header;

typedef struct {
    UdsRelayV3Header header;
    uint16_t body_length;
    uint8_t body[UDS_RELAY_V3_MAX_LOGICAL_BODY];
} UdsRelayV3Message;

typedef struct {
    bool used;
    UdsRelayV3Header header;
    uint8_t received_mask;
    uint16_t fragment_lengths[2];
    uint64_t last_ms;
    uint8_t body[UDS_RELAY_V3_MAX_LOGICAL_BODY];
} UdsRelayV3ReassemblyEntry;

typedef struct {
    UdsRelayV3ReassemblyEntry entries[UDS_RELAY_V3_MAX_REASSEMBLIES];
} UdsRelayV3Reassembler;

typedef struct {
    uint8_t room_id[16];
    uint8_t scope[16];
    uint8_t node_info[16][0x28];
    uint32_t node_generations[16];
    uint32_t roster_version;
    uint16_t local_node;
    uint16_t valid_mask;
} UdsRelayV3Peers;

bool udsRelayV3HeaderEncode(uint8_t *out, size_t out_capacity,
                            const UdsRelayV3Header *header);
bool udsRelayV3HeaderDecode(const uint8_t *packet, size_t packet_length,
                            UdsRelayV3Header *out);
size_t udsRelayV3ReassemblerSize(void);
void udsRelayV3ReassemblerInit(UdsRelayV3Reassembler *state);
bool udsRelayV3ReassemblerPush(UdsRelayV3Reassembler *state,
                               const uint8_t *packet, size_t packet_length,
                               uint64_t now_ms, UdsRelayV3Message *out);
bool udsRelayV3BodyValidate(uint8_t packet_type, uint8_t flags,
                            const uint8_t *body, uint16_t body_length);
bool udsRelayV3HostDescriptorPrepare(uint8_t network_info[0x108],
                                     uint8_t host_node_info[0x28],
                                     const uint8_t mac[6]);
uint32_t udsRelayV3Fnv1a32(const uint8_t *data, size_t length);
bool udsRelayV3UuidV4Prepare(uint8_t identifier[16]);
bool udsRelayV3UuidV4Valid(const uint8_t identifier[16]);
bool udsRelayV3HostParse(const char *data, size_t length, uint8_t address[4],
                         uint16_t *port);
bool udsRelayV3RegisterBodyBuild(uint8_t out[0x30], const uint8_t client_id[16],
                                 const uint8_t nonce[16], uint8_t channel,
                                 uint16_t pin);
bool udsRelayV3StatusQueryPrepare(uint8_t out[20], const uint8_t nonce[8]);
bool udsRelayV3QueryReplyMatches(const uint8_t *packet, size_t length,
                                  uint8_t expected_type, const uint8_t nonce[8]);
bool udsRelayV3HeartbeatBodyBuild(uint8_t out[0x18], const uint8_t scope[16],
                                  uint32_t roster_version);
uint32_t udsRelayV3RetryDelayMs(uint32_t attempt);
uint64_t udsRelayV3DeadlineStart(uint64_t started_ms, uint64_t now_ms);
bool udsRelayV3DeadlineExpired(uint64_t started_ms, uint64_t now_ms);
bool udsRelayV3PrejoinAdvertMatches(uint8_t flags, const uint8_t *body,
                                    uint16_t body_length,
                                    const uint8_t selected_room[16]);
bool udsRelayV3PeersApply(UdsRelayV3Peers *peers, const uint8_t *body,
                          uint16_t body_length,
                          const uint8_t expected_room[16],
                          const uint8_t expected_scope[16],
                          const uint8_t expected_own_node_info[0x28],
                          uint8_t max_nodes,
                          uint16_t *out_changed);
bool udsRelayV3MessageEncode(uint8_t packet_type, uint8_t flags,
                             const uint8_t token[16], const uint8_t *body,
                             uint16_t body_length, uint32_t fragment_id,
                             uint8_t out_packets[2][UDS_RELAY_V3_MAX_DATAGRAM],
                             uint16_t out_lengths[2], uint8_t *out_count);

#endif
