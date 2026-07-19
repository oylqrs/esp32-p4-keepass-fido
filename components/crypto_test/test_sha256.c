#include "test_sha256.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "canokey_esp32p4.h"
#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "sha.h"

static const char *TAG = "crypto_test_sha256";

static void dump_hex(const char *label, const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "%s:", label);
    ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_INFO);
}

static bool digest_equal(const uint8_t a[SHA256_DIGEST_LENGTH],
                         const uint8_t b[SHA256_DIGEST_LENGTH])
{
    return memcmp(a, b, SHA256_DIGEST_LENGTH) == 0;
}

void test_sha256(void)
{
    static const uint8_t expected_abc[SHA256_DIGEST_LENGTH] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const char *msg = "abc";
    uint8_t mbedtls_out[SHA256_DIGEST_LENGTH];
    uint8_t canokey_out[SHA256_DIGEST_LENGTH];

    ESP_LOGI(TAG, "start SHA256 test, msg=\"%s\"", msg);

    esp_err_t init_ret = canokey_esp32p4_crypto_init();
    if (init_ret != ESP_OK) {
        ESP_LOGE(TAG, "canokey crypto init failed: %s", esp_err_to_name(init_ret));
        return;
    }

    int mbedtls_ret = mbedtls_sha256((const unsigned char *)msg, strlen(msg),
                                     mbedtls_out, 0);
    if (mbedtls_ret != 0) {
        ESP_LOGE(TAG, "mbedtls_sha256 failed: -0x%04x", -mbedtls_ret);
        return;
    }

    sha256_raw((const uint8_t *)msg, strlen(msg), canokey_out);

    dump_hex("mbedtls sha256", mbedtls_out, sizeof(mbedtls_out));
    dump_hex("canokey sha256", canokey_out, sizeof(canokey_out));
    dump_hex("expected sha256", expected_abc, sizeof(expected_abc));

    if (!digest_equal(canokey_out, expected_abc)) {
        ESP_LOGE(TAG, "canokey-core sha256 result mismatch");
        return;
    }
    if (!digest_equal(canokey_out, mbedtls_out)) {
        ESP_LOGE(TAG, "canokey-core sha256 differs from mbedtls");
        return;
    }

    ESP_LOGI(TAG, "canokey-core sha256 OK");
}
