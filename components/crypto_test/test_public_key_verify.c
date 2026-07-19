#include "test_public_key_verify.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "esp_log.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

static const char *TAG = "crypto_test_pubkey";

static int verify_p256_raw_signature(const uint8_t *pub,
                                     const uint8_t *sig,
                                     const uint8_t *digest,
                                     size_t digest_len)
{
    int ret;
    uint8_t sec1_pub[65] = {0x04};
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        goto cleanup;
    }

    memcpy(sec1_pub + 1, pub, 64);
    ret = mbedtls_ecp_point_read_binary(&grp, &q, sec1_pub, sizeof(sec1_pub));
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_mpi_read_binary(&r, sig, 32);
    if (ret != 0) {
        goto cleanup;
    }
    ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_ecdsa_verify(&grp, digest, digest_len, &q, &r, &s);

cleanup:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

void test_public_key_verify(void)
{
    ecc_key_t key = {0};
    uint8_t saved_pub[64] = {0};
    uint8_t sig[64] = {0};
    const uint8_t digest[32] = {
        0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1,
        0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c,
        0x4a, 0xc8, 0x9b, 0x1a, 0xdf, 0x57, 0xf2, 0x8f,
        0x2f, 0x9d, 0x09, 0xaf, 0x10, 0x7e, 0xe8, 0xf0,
    };

    ESP_LOGI(TAG, "start P-256 public key verify test");

    ESP_LOGI(TAG, "Step 1: call CanoKey crypto to generate key");
    int ret = ecc_generate(SECP256R1, &key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Step 1 failed: ecc_generate(SECP256R1) ret=%d", ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Step 1 OK: key generated");

    ESP_LOGI(TAG, "Step 2: save public key");
    memcpy(saved_pub, key.pub, sizeof(saved_pub));
    ESP_LOGI(TAG, "Step 2 OK: public key saved");
    ESP_LOG_BUFFER_HEXDUMP(TAG, saved_pub, sizeof(saved_pub), ESP_LOG_INFO);

    ESP_LOGI(TAG, "Step 3: sign digest with CanoKey crypto");
    ret = ecc_sign(SECP256R1, &key, digest, sizeof(digest), sig);
    if (ret != 0) {
        ESP_LOGE(TAG, "Step 3 failed: ecc_sign(SECP256R1) ret=%d", ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Step 3 OK: signature generated");
    ESP_LOG_BUFFER_HEXDUMP(TAG, sig, sizeof(sig), ESP_LOG_INFO);

    ESP_LOGI(TAG, "Step 4: verify Q=dG and verify signature with saved public key");
    ret = ecc_verify_private_key(SECP256R1, &key);
    if (ret != 1) {
        ESP_LOGE(TAG, "Step 4 failed: Q=dG verify ret=%d", ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Step 4 OK: Q=dG verified");

    ret = verify_p256_raw_signature(saved_pub, sig, digest, sizeof(digest));
    if (ret != 0) {
        ESP_LOGE(TAG, "Step 4 failed: ECDSA verify ret=-0x%04x", (unsigned)-ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Step 4 OK: signature verified with saved public key");

    ESP_LOGI(TAG, "P-256 public key verify test OK");

cleanup:
    memset(&key, 0, sizeof(key));
    memset(saved_pub, 0, sizeof(saved_pub));
    memset(sig, 0, sizeof(sig));
}
