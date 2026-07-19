#include "test_ecdsa_sign.h"

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

static const char *TAG = "crypto_test_ecdsa";

static int write_mpi_32(const char *label, const mbedtls_mpi *value, uint8_t out[32])
{
    int ret = mbedtls_mpi_write_binary(value, out, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "%s write failed: -0x%04x", label, (unsigned)-ret);
        return ret;
    }

    ESP_LOGI(TAG, "%s 32bytes:", label);
    ESP_LOG_BUFFER_HEXDUMP(TAG, out, 32, ESP_LOG_INFO);
    return 0;
}

void test_ecdsa_sign(void)
{
    static const uint8_t private_key[32] = {
        0x50, 0x5a, 0x4f, 0xcf, 0xa6, 0xe2, 0x20, 0xba,
        0x55, 0x09, 0x58, 0xab, 0xc4, 0xf2, 0x39, 0x05,
        0xe9, 0xdb, 0x2a, 0x2b, 0x5a, 0xca, 0x29, 0xad,
        0x72, 0x89, 0x36, 0x70, 0x2f, 0x9a, 0x69, 0xea,
    };
    static const uint8_t message[] = "hello fido";
    static const char personalization[] = "crypto_test_ecdsa_sign";

    int ret;
    uint8_t hash[32] = {0};
    uint8_t signature[64] = {0};
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "start ECDSA sign test");
    ESP_LOGI(TAG, "message: %s", (const char *)message);

    ret = mbedtls_sha256(message, strlen((const char *)message), hash, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "SHA256 failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }
    ESP_LOGI(TAG, "SHA256 hash:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, hash, sizeof(hash), ESP_LOG_INFO);

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

    ret = mbedtls_mpi_read_binary(&d, private_key, sizeof(private_key));
    if (ret != 0) {
        ESP_LOGE(TAG, "private key read failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "sign: mbedtls_ecdsa_sign()");
    ret = mbedtls_ecdsa_sign(&grp,
                             &r,
                             &s,
                             &d,
                             hash,
                             sizeof(hash),
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecdsa_sign failed: -0x%04x", (unsigned)-ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "signature format: r 32bytes || s 32bytes");
    ret = write_mpi_32("r", &r, signature);
    if (ret != 0) {
        goto cleanup;
    }
    ret = write_mpi_32("s", &s, signature + 32);
    if (ret != 0) {
        goto cleanup;
    }

    ESP_LOGI(TAG, "signature:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, signature, sizeof(signature), ESP_LOG_INFO);
    ESP_LOGI(TAG, "ECDSA sign test OK");

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    memset(hash, 0, sizeof(hash));
    memset(signature, 0, sizeof(signature));
}
