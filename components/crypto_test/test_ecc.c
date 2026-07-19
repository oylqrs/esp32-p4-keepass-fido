#include "test_ecc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "esp_log.h"

static const char *TAG = "crypto_test_ecc";

static void dump_hex(const char *label, const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "%s:", label);
    ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_INFO);
}

static bool all_zero(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

void test_ecc(void)
{
    ecc_key_t key = {0};
    const size_t key_len = PRIVATE_KEY_LENGTH[SECP256R1];
    const size_t pub_len = PUBLIC_KEY_LENGTH[SECP256R1];

    ESP_LOGI(TAG, "start canokey-core ECC P-256 test");

    int ret = ecc_generate(SECP256R1, &key);
    if (ret != 0) {
        ESP_LOGE(TAG, "ecc_generate(SECP256R1) failed: %d", ret);
        return;
    }

    if (key_len != 32 || pub_len != 64) {
        ESP_LOGE(TAG, "unexpected P-256 key length: pri=%u pub=%u",
                 (unsigned)key_len, (unsigned)pub_len);
        return;
    }

    dump_hex("Private", key.pri, key_len);
    dump_hex("Public X", key.pub, key_len);
    dump_hex("Public Y", key.pub + key_len, key_len);

    if (all_zero(key.pri, key_len) ||
        all_zero(key.pub, key_len) ||
        all_zero(key.pub + key_len, key_len)) {
        ESP_LOGE(TAG, "P-256 key contains all-zero field");
        return;
    }

    int verified = ecc_verify_private_key(SECP256R1, &key);
    if (verified != 1) {
        ESP_LOGE(TAG, "ecc_verify_private_key(SECP256R1) failed: %d", verified);
        return;
    }

    ESP_LOGI(TAG, "canokey-core ECC P-256 OK, COSE alg=-7, ES256");
    memset(&key, 0, sizeof(key));
}
