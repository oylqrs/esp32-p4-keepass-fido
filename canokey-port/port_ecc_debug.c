#include "ecc.h"
#include "esp_log.h"

static const char *TAG = "canokey_key";

int __real_ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig);
int __real_sign_with_private_key(int32_t alg_type,
                                 ecc_key_t *key,
                                 const uint8_t *input,
                                 size_t len,
                                 uint8_t *sig);
void __real_K__ed25519_sign(const unsigned char *m,
                            size_t mlen,
                            const K__ed25519_secret_key sk,
                            const K__ed25519_public_key pk,
                            K__ed25519_signature rs);

static const char *key_type_name(key_type_t type)
{
    switch (type) {
    case SECP256R1:
        return "SECP256R1";
    case ED25519:
        return "ED25519";
    case SM2:
        return "SM2";
    default:
        return "OTHER";
    }
}

static const char *cose_alg_name(int32_t alg_type)
{
    switch (alg_type) {
    case -7:
        return "ES256";
    case -8:
        return "EdDSA";
    default:
        return "UNKNOWN";
    }
}

int __wrap_ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig)
{
    if (key && type >= 0 && type < KEY_TYPE_PKC_END) {
        size_t pri_len = PRIVATE_KEY_LENGTH[type];
        ESP_LOGW(TAG, "key3 step: ecc_sign enter type=%d(%s) pri_len=%u sign_input_len=%u",
                 (int)type,
                 key_type_name(type),
                 (unsigned)pri_len,
                 (unsigned)len);
        ESP_LOGW(TAG, "key3 step: ecc_sign private key");
        ESP_LOG_BUFFER_HEXDUMP(TAG, key->pri, pri_len, ESP_LOG_WARN);
        ESP_LOGW(TAG, "key3 step: ecc_sign input");
        ESP_LOG_BUFFER_HEXDUMP(TAG, data_or_digest, len, ESP_LOG_WARN);
    } else {
        ESP_LOGW(TAG, "key3 step: ecc_sign private key unavailable type=%d key=%u sign_input_len=%u",
                 (int)type,
                 key ? 1 : 0,
                 (unsigned)len);
    }

    int ret = __real_ecc_sign(type, key, data_or_digest, len, sig);
    ESP_LOGW(TAG, "key3 step: ecc_sign exit ret=%d", ret);
    if (ret == 0 && type >= 0 && type < KEY_TYPE_PKC_END) {
        ESP_LOGW(TAG, "key3 step: ecc_sign raw signature len=%u",
                 (unsigned)SIGNATURE_LENGTH[type]);
        ESP_LOG_BUFFER_HEXDUMP(TAG, sig, SIGNATURE_LENGTH[type], ESP_LOG_WARN);
    }
    return ret;
}

void __wrap_K__ed25519_sign(const unsigned char *m,
                            size_t mlen,
                            const K__ed25519_secret_key sk,
                            const K__ed25519_public_key pk,
                            K__ed25519_signature rs)
{
    ESP_LOGW(TAG, "key3 step: K__ed25519_sign enter mlen=%u", (unsigned)mlen);
    ESP_LOGW(TAG, "key3 step: K__ed25519_sign message");
    ESP_LOG_BUFFER_HEXDUMP(TAG, m, mlen, ESP_LOG_WARN);
    ESP_LOGW(TAG, "key3 step: K__ed25519_sign secret key");
    ESP_LOG_BUFFER_HEXDUMP(TAG, sk, 32, ESP_LOG_WARN);
    ESP_LOGW(TAG, "key3 step: K__ed25519_sign public key");
    ESP_LOG_BUFFER_HEXDUMP(TAG, pk, 32, ESP_LOG_WARN);

    __real_K__ed25519_sign(m, mlen, sk, pk, rs);

    ESP_LOGW(TAG, "key3 step: K__ed25519_sign output rs len=64");
    ESP_LOG_BUFFER_HEXDUMP(TAG, rs, 64, ESP_LOG_WARN);
}

int __wrap_sign_with_private_key(int32_t alg_type,
                                 ecc_key_t *key,
                                 const uint8_t *input,
                                 size_t len,
                                 uint8_t *sig)
{
    ESP_LOGW(TAG,
             "key3 step: sign_with_private_key enter alg=%ld(%s) input_len=%u in_place=%u",
             (long)alg_type,
             cose_alg_name(alg_type),
             (unsigned)len,
             input == sig ? 1 : 0);
    ESP_LOGW(TAG, "key3 step: sign_with_private_key input authData||clientDataHash");
    ESP_LOG_BUFFER_HEXDUMP(TAG, input, len, ESP_LOG_WARN);

    int ret = __real_sign_with_private_key(alg_type, key, input, len, sig);
    ESP_LOGW(TAG, "key3 step: sign_with_private_key exit ret_sig_len=%d", ret);
    if (ret > 0) {
        ESP_LOGW(TAG, "key3 step: sign_with_private_key final signature");
        ESP_LOG_BUFFER_HEXDUMP(TAG, sig, (uint16_t)ret, ESP_LOG_WARN);
    }

    return ret;
}
