#include "test_ecdsa_verify.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"

static const char *TAG = "crypto_test_verify";

static void dump_mpi_32(const char *label, const mbedtls_mpi *value)
{
    uint8_t buf[32] = {0};
    int ret = mbedtls_mpi_write_binary(value, buf, sizeof(buf));
    if (ret != 0) {
        ESP_LOGE(TAG, "%s dump failed: -0x%04x", label, (unsigned)-ret);
        return;
    }

    ESP_LOGI(TAG, "%s:", label);
    ESP_LOG_BUFFER_HEXDUMP(TAG, buf, sizeof(buf), ESP_LOG_INFO);
}

void test_ecdsa_verify(void)
{
    static const uint8_t message[] = "hello fido";
    static const char personalization[] = "crypto_test_ecdsa_verify";

    int ret;
    uint8_t hash[32] = {0};
    uint8_t public_key[65] = {0};
    size_t public_key_len = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "start ECDSA verify test");

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                (const uint8_t *)personalization,
                                strlen(personalization));
    if (ret != 0) {
        ESP_LOGE(TAG, "CTR_DRBG seed failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "P-256 group load failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "Step 1: generate private key");
    ESP_LOGI(TAG, "Step 2: generate public key");
    ret = mbedtls_ecp_gen_keypair(&grp,
                                  &d,
                                  &q,
                                  mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "keypair generate failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }
    dump_mpi_32("private key d", &d);

    ret = mbedtls_ecp_point_write_binary(&grp,
                                         &q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &public_key_len,
                                         public_key,
                                         sizeof(public_key));
    if (ret != 0) {
        ESP_LOGE(TAG, "public key export failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "public key Q:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, public_key, public_key_len, ESP_LOG_INFO);

    ESP_LOGI(TAG, "Step 3: hash(message)");
    ESP_LOGI(TAG, "message: %s", (const char *)message);
    ret = mbedtls_sha256(message, strlen((const char *)message), hash, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "SHA256 failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "hash:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, hash, sizeof(hash), ESP_LOG_INFO);

    ESP_LOGI(TAG, "Step 4: ECDSA sign");
    ret = mbedtls_ecdsa_sign(&grp,
                             &r,
                             &s,
                             &d,
                             hash,
                             sizeof(hash),
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "ECDSA sign failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }
    dump_mpi_32("signature r", &r);
    dump_mpi_32("signature s", &s);

    ESP_LOGI(TAG, "Step 5: ECDSA verify");
    ret = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &q, &r, &s);
    ESP_LOGI(TAG, "mbedtls_ecdsa_verify() return: %d", ret);
    if (ret != 0) {
        ESP_LOGE(TAG, "ECDSA verify failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "PASS");

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    memset(hash, 0, sizeof(hash));
    memset(public_key, 0, sizeof(public_key));
}
