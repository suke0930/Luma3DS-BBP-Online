/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UDS_BEACON_SCAN_H
#define UDS_BEACON_SCAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Type21 wire fields are big-endian. */
typedef struct {
    uint32_t wlan_comm_id;
    uint8_t id8;
    uint32_t network_id;
    uint8_t max_nodes;
} UdsBeaconType21Identity;

typedef struct {
    uint8_t host_mac[6];
    uint16_t channel;
    uint8_t initialized;
    uint8_t reserved;
    uint32_t wlan_comm_id;
    uint8_t id8;
    uint8_t reserved2[3];
    uint32_t network_id;
    uint8_t max_nodes;
    uint8_t reserved3[3];
} UdsBeaconCandidateIdentity;

/* Frame: 12-byte UDS header followed by 802.11 information elements. */
bool udsBeaconMatchesScanQuery(const uint8_t *frame, size_t frame_len,
                               uint32_t wlan_comm_id, uint8_t id8);

/* Uses the last recognized Type21 identity. */
bool udsBeaconExtractType21Identity(const uint8_t *frame, size_t frame_len,
                                    UdsBeaconType21Identity *out);

bool udsBeaconScanQueryMatchesIdentity(uint32_t wlan_comm_id, uint8_t id8,
                                       const UdsBeaconType21Identity *identity);

/* A changed key at UINT32_MAX fails without wrapping the generation. */
bool udsBeaconAdvanceCandidateGeneration(uint32_t current_generation,
                                         bool current_valid,
                                         bool key_changed,
                                         uint32_t *out_generation);

bool udsBeaconCandidateMatchesCmd1E(const uint8_t *input, size_t input_len,
                                    const UdsBeaconCandidateIdentity *candidate);

bool udsBeaconBuildSemanticFrame(const uint8_t *descriptor,
                                 size_t descriptor_len, uint8_t *out_frame,
                                 size_t out_capacity, size_t *out_len,
                                 UdsBeaconCandidateIdentity *out_identity);

#endif
