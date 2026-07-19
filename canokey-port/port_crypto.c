#include "canokey_esp32p4.h"

#include <stdbool.h>
#include <string.h>

#include "aes.h"
#include "ecc.h"
#include "ecc_impl.h"
#include "esp_log.h"
#include "hmac.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "rand.h"
#include "sha.h"

static const char *TAG = "canokey_crypto";

static mbedtls_sha256_context s_sha256_ctx;
static bool s_sha256_active;

static const uint8_t p256_n[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

static const uint8_t p256_gx[32] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
};

static const uint8_t p256_gy[32] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};

static void reverse32(const uint8_t in[32], uint8_t out[32])
{
    for (size_t i = 0; i < 32; ++i) {
        out[i] = in[31 - i];
    }
}

static bool is_zero32(const uint8_t value[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; ++i) {
        acc |= value[i];
    }
    return acc == 0;
}

static int cmp_be32(const uint8_t a[32], const uint8_t b[32])
{
    for (size_t i = 0; i < 32; ++i) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    return 0;
}

static bool p256_private_key_valid(const uint8_t pri[32])
{
    return !is_zero32(pri) && cmp_be32(pri, p256_n) < 0;
}

static void ecc_point_from_be(ecc_point_t *point, const uint8_t x_be[32], const uint8_t y_be[32])
{
    reverse32(x_be, point->x);
    reverse32(y_be, point->y);
    point->len = 32;
}

static void ecc_point_to_be(const ecc_point_t *point, uint8_t x_be[32], uint8_t y_be[32])
{
    reverse32(point->x, x_be);
    reverse32(point->y, y_be);
}

static int p256_point_multiply(const uint8_t scalar_be[32], const uint8_t x_be[32],
                               const uint8_t y_be[32], bool verify_first,
                               uint8_t rx_be[32], uint8_t ry_be[32])
{
    ecc_point_t point;
    ecc_point_t result;
    uint8_t scalar_le[32];

    if (!p256_private_key_valid(scalar_be)) {
        return -1;
    }

    reverse32(scalar_be, scalar_le);
    ecc_point_from_be(&point, x_be, y_be);

    if (esp_ecc_point_multiply(&point, scalar_le, &result, verify_first) != 0) {
        return -1;
    }

    ecc_point_to_be(&result, rx_be, ry_be);
    return 0;
}

int K__short_weierstrass_generate(key_type_t type, ecc_key_t *key)
{
    if (type != SECP256R1 || key == NULL) {
        return -1;
    }

    do {
        random_buffer(key->pri, 32);
    } while (!p256_private_key_valid(key->pri));

    return p256_point_multiply(key->pri, p256_gx, p256_gy, false, key->pub, key->pub + 32);
}

int K__short_weierstrass_verify_private_key(const key_type_t type, const ecc_key_t *key)
{
    if (type != SECP256R1 || key == NULL) {
        return 0;
    }

    return p256_private_key_valid(key->pri) ? 1 : 0;
}

int K__short_weierstrass_complete_key(key_type_t type, ecc_key_t *key)
{
    if (type != SECP256R1 || key == NULL) {
        return -1;
    }

    return p256_point_multiply(key->pri, p256_gx, p256_gy, false, key->pub, key->pub + 32);
}

int K__short_weierstrass_ecdh(key_type_t type, const uint8_t *priv_key,
                              const uint8_t *receiver_pub_key, uint8_t *out)
{
    if (type != SECP256R1 || priv_key == NULL || receiver_pub_key == NULL || out == NULL) {
        return -1;
    }

    return p256_point_multiply(priv_key, receiver_pub_key, receiver_pub_key + 32, true, out, out + 32);
}

int K__short_weierstrass_sign(key_type_t type, const ecc_key_t *key,
                              const uint8_t *data_or_digest, size_t len, uint8_t *sig)
{
    if (type != SECP256R1 || key == NULL || data_or_digest == NULL || sig == NULL || len != 32) {
        return -1;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_mpi r;
    mbedtls_mpi s;
    int ret = -1;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        goto out;
    }
    if (mbedtls_mpi_read_binary(&d, key->pri, 32) != 0) {
        goto out;
    }
    if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, data_or_digest, 32, mbedtls_rnd, NULL) != 0) {
        goto out;
    }
    if (mbedtls_mpi_write_binary(&r, sig, 32) != 0) {
        goto out;
    }
    if (mbedtls_mpi_write_binary(&s, sig + 32, 32) != 0) {
        goto out;
    }

    ret = 0;

out:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

static int aes_ecb_crypt(const uint8_t *in, uint8_t *out, const uint8_t *key,
                         unsigned int keybits, int mode)
{
    if (in == NULL || out == NULL || key == NULL) {
        return -1;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret;
    if (mode == MBEDTLS_AES_ENCRYPT) {
        ret = mbedtls_aes_setkey_enc(&ctx, key, keybits);
    } else {
        ret = mbedtls_aes_setkey_dec(&ctx, key, keybits);
    }

    if (ret == 0) {
        ret = mbedtls_aes_crypt_ecb(&ctx, mode, in, out);
    }

    mbedtls_aes_free(&ctx);
    return ret == 0 ? 0 : -1;
}

int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key)
{
    return aes_ecb_crypt(in, out, key, 128, MBEDTLS_AES_ENCRYPT);
}

int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key)
{
    return aes_ecb_crypt(in, out, key, 128, MBEDTLS_AES_DECRYPT);
}

int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key)
{
    return aes_ecb_crypt(in, out, key, 256, MBEDTLS_AES_ENCRYPT);
}

int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key)
{
    return aes_ecb_crypt(in, out, key, 256, MBEDTLS_AES_DECRYPT);
}

void sha256_init(sha256_ctx_t *ctx)
{
    (void)ctx;

    if (s_sha256_active) {
        mbedtls_sha256_free(&s_sha256_ctx);
        s_sha256_active = false;
    }

    mbedtls_sha256_init(&s_sha256_ctx);
    if (mbedtls_sha256_starts(&s_sha256_ctx, 0) != 0) {
        ESP_LOGE(TAG, "mbedtls_sha256_starts failed");
        mbedtls_sha256_free(&s_sha256_ctx);
        return;
    }

    s_sha256_active = true;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    (void)ctx;

    if (!s_sha256_active) {
        ESP_LOGE(TAG, "sha256_update called before sha256_init");
        return;
    }

    if (mbedtls_sha256_update(&s_sha256_ctx, data, len) != 0) {
        ESP_LOGE(TAG, "mbedtls_sha256_update failed");
        mbedtls_sha256_free(&s_sha256_ctx);
        s_sha256_active = false;
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_LENGTH])
{
    (void)ctx;

    if (!s_sha256_active) {
        ESP_LOGE(TAG, "sha256_final called before sha256_init");
        memset(digest, 0, SHA256_DIGEST_LENGTH);
        return;
    }

    if (mbedtls_sha256_finish(&s_sha256_ctx, digest) != 0) {
        ESP_LOGE(TAG, "mbedtls_sha256_finish failed");
        memset(digest, 0, SHA256_DIGEST_LENGTH);
    }

    mbedtls_sha256_free(&s_sha256_ctx);
    s_sha256_active = false;
}

static esp_err_t check_sha256_vector(const uint8_t *data, size_t len,
                                     const uint8_t expected[SHA256_DIGEST_LENGTH])
{
    uint8_t digest[SHA256_DIGEST_LENGTH];

    sha256_raw(data, len, digest);
    if (memcmp(digest, expected, sizeof(digest)) != 0) {
        ESP_LOGE(TAG, "SHA256 selftest failed");
        ESP_LOG_BUFFER_HEXDUMP(TAG, digest, sizeof(digest), ESP_LOG_ERROR);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t check_hmac_sha256_vector(const uint8_t *key, size_t key_len,
                                          const uint8_t *data, size_t data_len,
                                          const uint8_t expected[SHA256_DIGEST_LENGTH])
{
    uint8_t digest[SHA256_DIGEST_LENGTH];

    hmac_sha256(key, key_len, data, data_len, digest);
    if (memcmp(digest, expected, sizeof(digest)) != 0) {
        ESP_LOGE(TAG, "HMAC-SHA256 selftest failed");
        ESP_LOG_BUFFER_HEXDUMP(TAG, digest, sizeof(digest), ESP_LOG_ERROR);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t check_aes256_ecb_vector(const uint8_t key[32],
                                         const uint8_t plain[16],
                                         const uint8_t expected[16])
{
    uint8_t cipher[16];
    uint8_t roundtrip[16];

    if (aes256_enc(plain, cipher, key) != 0) {
        ESP_LOGE(TAG, "AES-256 ECB encrypt failed");
        return ESP_FAIL;
    }
    if (memcmp(cipher, expected, sizeof(cipher)) != 0) {
        ESP_LOGE(TAG, "AES-256 ECB selftest encrypt mismatch");
        ESP_LOG_BUFFER_HEXDUMP(TAG, cipher, sizeof(cipher), ESP_LOG_ERROR);
        return ESP_FAIL;
    }
    if (aes256_dec(cipher, roundtrip, key) != 0) {
        ESP_LOGE(TAG, "AES-256 ECB decrypt failed");
        return ESP_FAIL;
    }
    if (memcmp(roundtrip, plain, sizeof(roundtrip)) != 0) {
        ESP_LOGE(TAG, "AES-256 ECB selftest decrypt mismatch");
        ESP_LOG_BUFFER_HEXDUMP(TAG, roundtrip, sizeof(roundtrip), ESP_LOG_ERROR);
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t canokey_esp32p4_crypto_init(void)
{
    /*
     * CanoKey Core uses canokey-crypto with ESP-IDF mbedTLS/PSA enabled.
     * Hash/cipher helpers initialize PSA on demand; random_buffer() is provided
     * by port_random.c and backed by esp_random().
     */
    ESP_LOGI(TAG, "crypto port ready");
    return ESP_OK;
}

esp_err_t canokey_esp32p4_crypto_selftest(void)
{
    static const uint8_t empty_sha256[SHA256_DIGEST_LENGTH] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    static const uint8_t abc_sha256[SHA256_DIGEST_LENGTH] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const uint8_t hmac_key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const uint8_t hmac_sha256_hi_there[SHA256_DIGEST_LENGTH] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    static const uint8_t aes256_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t aes256_plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    static const uint8_t aes256_cipher[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };

    if (check_sha256_vector((const uint8_t *)"", 0, empty_sha256) != ESP_OK) {
        return ESP_FAIL;
    }
    if (check_sha256_vector((const uint8_t *)"abc", 3, abc_sha256) != ESP_OK) {
        return ESP_FAIL;
    }
    if (check_hmac_sha256_vector(hmac_key, sizeof(hmac_key),
                                 (const uint8_t *)"Hi There", strlen("Hi There"),
                                 hmac_sha256_hi_there) != ESP_OK) {
        return ESP_FAIL;
    }
    if (check_aes256_ecb_vector(aes256_key, aes256_plain, aes256_cipher) != ESP_OK) {
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "SHA256/HMAC-SHA256/AES-256-ECB selftest passed");
    return ESP_OK;
}
