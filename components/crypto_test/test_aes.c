#include "test_aes.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "canokey_esp32p4.h"
#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/aes.h"

static const char *TAG = "crypto_test_aes";

static void dump_hex(const char *label, const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "%s:", label);
    ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_INFO);
}

static bool block_equal(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16) == 0;
}

static bool mbedtls_aes256_ecb_encrypt(const uint8_t plain[16],
                                       uint8_t cipher[16],
                                       const uint8_t key[32])
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plain, cipher);
    }

    mbedtls_aes_free(&ctx);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls AES-256 ECB encrypt failed: -0x%04x", -ret);
        return false;
    }

    return true;
}

void test_aes(void)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    static const uint8_t expected_cipher[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };
    uint8_t canokey_cipher[16];
    uint8_t mbedtls_cipher[16];
    uint8_t roundtrip[16];

    ESP_LOGI(TAG, "start AES-256 ECB test");

    esp_err_t init_ret = canokey_esp32p4_crypto_init();
    if (init_ret != ESP_OK) {
        ESP_LOGE(TAG, "canokey crypto init failed: %s", esp_err_to_name(init_ret));
        return;
    }

    if (aes256_enc(plain, canokey_cipher, key) != 0) {
        ESP_LOGE(TAG, "canokey-core AES-256 ECB encrypt failed");
        return;
    }
    if (aes256_dec(canokey_cipher, roundtrip, key) != 0) {
        ESP_LOGE(TAG, "canokey-core AES-256 ECB decrypt failed");
        return;
    }
    if (!mbedtls_aes256_ecb_encrypt(plain, mbedtls_cipher, key)) {
        return;
    }

    dump_hex("canokey aes-256-ecb cipher", canokey_cipher, sizeof(canokey_cipher));
    dump_hex("mbedtls aes-256-ecb cipher", mbedtls_cipher, sizeof(mbedtls_cipher));
    dump_hex("expected aes-256-ecb cipher", expected_cipher, sizeof(expected_cipher));

    if (!block_equal(canokey_cipher, expected_cipher)) {
        ESP_LOGE(TAG, "canokey-core AES-256 ECB cipher mismatch");
        return;
    }
    if (!block_equal(canokey_cipher, mbedtls_cipher)) {
        ESP_LOGE(TAG, "canokey-core AES-256 ECB differs from mbedtls");
        return;
    }
    if (!block_equal(roundtrip, plain)) {
        ESP_LOGE(TAG, "canokey-core AES-256 ECB decrypt roundtrip mismatch");
        dump_hex("roundtrip plain", roundtrip, sizeof(roundtrip));
        return;
    }

    ESP_LOGI(TAG, "canokey-core AES-256 ECB OK");
}
