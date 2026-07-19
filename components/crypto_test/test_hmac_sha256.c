#include "test_hmac_sha256.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "canokey_esp32p4.h"
#include "esp_err.h"
#include "esp_log.h"
#include "hmac.h"
#include "mbedtls/md.h"

static const char *TAG = "crypto_test_hmac_sha256";

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

static bool mbedtls_hmac_sha256(const uint8_t *key, size_t key_len,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t out[SHA256_DIGEST_LENGTH])
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        ESP_LOGE(TAG, "mbedtls_md_info_from_type failed");
        return false;
    }

    int ret = mbedtls_md_hmac(md_info, key, key_len, msg, msg_len, out);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_md_hmac failed: -0x%04x", -ret);
        return false;
    }

    return true;
}

static bool check_hmac_sha256_one_shot(const char *name,
                                       const uint8_t *key, size_t key_len,
                                       const uint8_t *msg, size_t msg_len,
                                       const uint8_t expected[SHA256_DIGEST_LENGTH])
{
    uint8_t mbedtls_out[SHA256_DIGEST_LENGTH];
    uint8_t canokey_out[SHA256_DIGEST_LENGTH];

    hmac_sha256(key, key_len, msg, msg_len, canokey_out);
    if (!mbedtls_hmac_sha256(key, key_len, msg, msg_len, mbedtls_out)) {
        return false;
    }

    dump_hex(name, canokey_out, sizeof(canokey_out));

    if (!digest_equal(canokey_out, expected)) {
        ESP_LOGE(TAG, "%s expected result mismatch", name);
        dump_hex("expected hmac-sha256", expected, SHA256_DIGEST_LENGTH);
        return false;
    }
    else{
        ESP_LOGI(TAG, "%s expected result matches", name);
    }
    if (!digest_equal(canokey_out, mbedtls_out)) {
        ESP_LOGE(TAG, "%s differs from mbedtls", name);
        dump_hex("mbedtls hmac-sha256", mbedtls_out, sizeof(mbedtls_out));
        return false;
    }
    else{
        ESP_LOGI(TAG, "%s matches mbedtls", name);
    }
    
    return true;
}

static bool check_hmac_sha256_streaming(void)
{
    static const uint8_t key[] = "Jefe";
    static const uint8_t part1[] = "what do ";
    static const uint8_t part2[] = "ya want ";
    static const uint8_t part3[] = "for nothing?";
    static const uint8_t expected[SHA256_DIGEST_LENGTH] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    uint8_t canokey_out[SHA256_DIGEST_LENGTH];
    HMAC_SHA256_CTX ctx;

    hmac_sha256_Init(&ctx, key, strlen((const char *)key));
    hmac_sha256_Update(&ctx, part1, strlen((const char *)part1));
    hmac_sha256_Update(&ctx, part2, strlen((const char *)part2));
    hmac_sha256_Update(&ctx, part3, strlen((const char *)part3));
    hmac_sha256_Final(&ctx, canokey_out);

    dump_hex("streaming hmac-sha256", canokey_out, sizeof(canokey_out));

    if (!digest_equal(canokey_out, expected)) {
        ESP_LOGE(TAG, "streaming expected result mismatch");
        dump_hex("expected hmac-sha256", expected, SHA256_DIGEST_LENGTH);
        return false;
    }

    return true;
}

void test_hmac_sha256(void)
{
    static const uint8_t rfc4231_key_1[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const uint8_t rfc4231_expected_1[SHA256_DIGEST_LENGTH] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    static const uint8_t rfc4231_expected_6[SHA256_DIGEST_LENGTH] = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
        0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
        0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
        0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
    };
    static const uint8_t msg_1[] = "Hi There";
    static const uint8_t msg_6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t rfc4231_key_6[131];

    ESP_LOGI(TAG, "start HMAC-SHA256 test");
    memset(rfc4231_key_6, 0xaa, sizeof(rfc4231_key_6));

    esp_err_t init_ret = canokey_esp32p4_crypto_init();
    if (init_ret != ESP_OK) {
        ESP_LOGE(TAG, "canokey crypto init failed: %s", esp_err_to_name(init_ret));
        return;
    }

    if (!check_hmac_sha256_one_shot("rfc4231 case 1",
                                    rfc4231_key_1, sizeof(rfc4231_key_1),
                                    msg_1, strlen((const char *)msg_1),
                                    rfc4231_expected_1)) {
        return;
    }
    if (!check_hmac_sha256_streaming()) {
        return;
    }
    if (!check_hmac_sha256_one_shot("rfc4231 case 6 long key",
                                    rfc4231_key_6, sizeof(rfc4231_key_6),
                                    msg_6, strlen((const char *)msg_6),
                                    rfc4231_expected_6)) {
        return;
    }

    ESP_LOGI(TAG, "canokey-core HMAC-SHA256 OK");
}
