// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_ESP32P4_MLDSA_NATIVE_H_
#define CANOKEY_ESP32P4_MLDSA_NATIVE_H_

#include <stddef.h>
#include <stdint.h>

size_t canokey_crypto_mldsa65_prepare_domain_separation_prefix(uint8_t *prefix,
                                                               const uint8_t *oid,
                                                               size_t oid_len,
                                                               const uint8_t *ctx,
                                                               size_t ctx_len,
                                                               uint8_t prehash);

int canokey_crypto_mldsa65_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int canokey_crypto_mldsa65_signature_internal(uint8_t *sig,
                                              size_t *sig_len,
                                              const uint8_t *msg,
                                              size_t msg_len,
                                              const uint8_t *prefix,
                                              size_t prefix_len,
                                              const uint8_t *rnd,
                                              const uint8_t *sk,
                                              int randomized);

#endif
