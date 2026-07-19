#include "test_fido_storage_loop.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "canokey_esp32p4.h"
#include "esp_err.h"
#include "esp_log.h"
#include "fs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"

#define FIDO_LOOP_CREDENTIAL_DB_FILE "fido_loop_credential.db"
#define FIDO_LOOP_PRIVATE_KEY_LEN    32
#define FIDO_LOOP_PUBLIC_KEY_LEN     65
#define FIDO_LOOP_RP_ID_HASH_LEN     32
#define FIDO_LOOP_CLIENT_HASH_LEN    32
#define FIDO_LOOP_AUTH_DATA_LEN      37
#define FIDO_LOOP_FLAGS_UP           0x01

static const char *TAG = "fido_storage_loop";

typedef struct {
    uint8_t private_key[FIDO_LOOP_PRIVATE_KEY_LEN];
    uint8_t credential_id[32];
    uint16_t credential_id_len;
    char rp_id[64];
    uint32_t sign_count;
} fido_loop_credential_t;

typedef struct {
    bool makecredential;
    bool private_key;
    bool storage_save;
    bool reboot_load;
    bool getassertion;
    bool ecdsa_sign;
    bool verify;
} fido_loop_check_t;

static void log_summary(const fido_loop_check_t *check)
{
    bool all_pass = check->makecredential &&
                    check->private_key &&
                    check->storage_save &&
                    check->reboot_load &&
                    check->getassertion &&
                    check->ecdsa_sign &&
                    check->verify;

    ESP_LOGI(TAG, "==============================");
    ESP_LOGI(TAG, "FIDO2 Storage Loop Test");
    ESP_LOGI(TAG, "MakeCredential   %s", check->makecredential ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "Private key      %s", check->private_key ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "Storage save     %s", check->storage_save ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "Reboot load      %s", check->reboot_load ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "GetAssertion     %s", check->getassertion ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "ECDSA sign       %s", check->ecdsa_sign ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "Verify           %s", check->verify ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "%s", all_pass ? "ALL PASS" : "FAIL");
    ESP_LOGI(TAG, "==============================");
}

static bool storage_save_credential(const fido_loop_credential_t *credential)
{
    int ret = write_file(FIDO_LOOP_CREDENTIAL_DB_FILE,
                         credential,
                         0,
                         sizeof(*credential),
                         1);
    if (ret != 0) {
        ESP_LOGE(TAG, "storage save failed: %d", ret);
        return false;
    }

    return true;
}

static bool storage_load_credential(fido_loop_credential_t *credential)
{
    int ret = read_file(FIDO_LOOP_CREDENTIAL_DB_FILE,
                        credential,
                        0,
                        sizeof(*credential));
    if (ret != sizeof(*credential)) {
        ESP_LOGE(TAG, "storage load failed: %d", ret);
        return false;
    }

    return true;
}

static bool build_getassertion_digest(const char *rp_id,
                                      const uint8_t client_data_hash[FIDO_LOOP_CLIENT_HASH_LEN],
                                      uint32_t sign_count,
                                      uint8_t auth_data[FIDO_LOOP_AUTH_DATA_LEN],
                                      uint8_t digest[32])
{
    uint8_t sign_input[FIDO_LOOP_AUTH_DATA_LEN + FIDO_LOOP_CLIENT_HASH_LEN] = {0};

    if (mbedtls_sha256((const uint8_t *)rp_id, strlen(rp_id), auth_data, 0) != 0) {
        ESP_LOGE(TAG, "rpIdHash sha256 failed");
        return false;
    }

    auth_data[32] = FIDO_LOOP_FLAGS_UP;
    auth_data[33] = (uint8_t)(sign_count >> 24);
    auth_data[34] = (uint8_t)(sign_count >> 16);
    auth_data[35] = (uint8_t)(sign_count >> 8);
    auth_data[36] = (uint8_t)sign_count;

    memcpy(sign_input, auth_data, FIDO_LOOP_AUTH_DATA_LEN);
    memcpy(sign_input + FIDO_LOOP_AUTH_DATA_LEN, client_data_hash, FIDO_LOOP_CLIENT_HASH_LEN);

    if (mbedtls_sha256(sign_input, sizeof(sign_input), digest, 0) != 0) {
        ESP_LOGE(TAG, "assertion digest sha256 failed");
        return false;
    }

    ESP_LOGI(TAG, "GetAssertion authData:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, auth_data, FIDO_LOOP_AUTH_DATA_LEN, ESP_LOG_INFO);
    ESP_LOGI(TAG, "GetAssertion digest:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, digest, 32, ESP_LOG_INFO);
    return true;
}

static bool import_public_key(const mbedtls_ecp_group *group,
                              const uint8_t public_key[FIDO_LOOP_PUBLIC_KEY_LEN],
                              mbedtls_ecp_point *q)
{
    int ret = mbedtls_ecp_point_read_binary(group,
                                            q,
                                            public_key,
                                            FIDO_LOOP_PUBLIC_KEY_LEN);
    if (ret != 0) {
        ESP_LOGE(TAG, "public key import failed: -0x%04x", (unsigned int)-ret);
        return false;
    }

    return true;
}

static void test_fido_storage_loop_run(void)
{
    static const uint8_t client_data_hash[FIDO_LOOP_CLIENT_HASH_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    static const char personalization[] = "fido_storage_loop";

    fido_loop_check_t check = {0};
    fido_loop_credential_t saved = {0};
    fido_loop_credential_t loaded = {0};
    uint8_t public_key[FIDO_LOOP_PUBLIC_KEY_LEN] = {0};
    uint8_t auth_data[FIDO_LOOP_AUTH_DATA_LEN] = {0};
    uint8_t digest[32] = {0};
    uint8_t private_key_after_reboot[FIDO_LOOP_PRIVATE_KEY_LEN] = {0};
    size_t public_key_len = 0;
    int ret;

    mbedtls_ecp_group group;
    mbedtls_ecp_point public_point;
    mbedtls_ecp_point verify_point;
    mbedtls_mpi private_d;
    mbedtls_mpi loaded_d;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&public_point);
    mbedtls_ecp_point_init(&verify_point);
    mbedtls_mpi_init(&private_d);
    mbedtls_mpi_init(&loaded_d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "MakeCredential -> storage save -> reboot -> storage load -> GetAssertion -> sign -> verify");

    if (canokey_esp32p4_crypto_init() != ESP_OK) {
        ESP_LOGE(TAG, "crypto init failed");
        goto cleanup;
    }

    esp_err_t flash_ret = canokey_esp32p4_flash_init();
    if (flash_ret != ESP_OK) {
        ESP_LOGE(TAG, "flash init failed: %s", esp_err_to_name(flash_ret));
        goto cleanup;
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                (const uint8_t *)personalization,
                                strlen(personalization));
    if (ret != 0) {
        ESP_LOGE(TAG, "CTR_DRBG seed failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }

    ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "P-256 group load failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "MakeCredential: generate private key");
    ret = mbedtls_ecp_gen_keypair(&group,
                                  &private_d,
                                  &public_point,
                                  mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "keypair generate failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }
    check.makecredential = true;

    ret = mbedtls_mpi_write_binary(&private_d,
                                   saved.private_key,
                                   sizeof(saved.private_key));
    if (ret != 0) {
        ESP_LOGE(TAG, "private key export failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }
    check.private_key = true;

    ret = mbedtls_ecp_point_write_binary(&group,
                                         &public_point,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &public_key_len,
                                         public_key,
                                         sizeof(public_key));
    if (ret != 0 || public_key_len != sizeof(public_key)) {
        ESP_LOGE(TAG, "public key export failed: ret=%d len=%u",
                 ret,
                 (unsigned int)public_key_len);
        goto cleanup;
    }

    memcpy(saved.credential_id,
           "loop-credential-id-000000000001",
           sizeof(saved.credential_id));
    saved.credential_id_len = sizeof(saved.credential_id);
    strcpy(saved.rp_id, "example.com");
    saved.sign_count = 0;

    ESP_LOGI(TAG, "storage save");
    if (!storage_save_credential(&saved)) {
        goto cleanup;
    }
    check.storage_save = true;

    ESP_LOGI(TAG, "reboot: clear RAM copy");
    memcpy(private_key_after_reboot, saved.private_key, sizeof(private_key_after_reboot));
    memset(&saved, 0, sizeof(saved));
    mbedtls_mpi_free(&private_d);
    mbedtls_mpi_init(&private_d);

    ESP_LOGI(TAG, "storage load");
    if (!storage_load_credential(&loaded)) {
        goto cleanup;
    }
    if (memcmp(loaded.private_key,
               private_key_after_reboot,
               sizeof(private_key_after_reboot)) != 0) {
        ESP_LOGE(TAG, "loaded private key mismatch");
        goto cleanup;
    }
    check.reboot_load = true;

    ESP_LOGI(TAG, "GetAssertion: build authData and digest");
    loaded.sign_count++;
    if (!build_getassertion_digest(loaded.rp_id,
                                   client_data_hash,
                                   loaded.sign_count,
                                   auth_data,
                                   digest)) {
        goto cleanup;
    }
    check.getassertion = true;

    ESP_LOGI(TAG, "ECDSA sign with loaded private key");
    ret = mbedtls_mpi_read_binary(&loaded_d,
                                  loaded.private_key,
                                  sizeof(loaded.private_key));
    if (ret != 0) {
        ESP_LOGE(TAG, "loaded private key import failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }

    ret = mbedtls_ecdsa_sign(&group,
                             &r,
                             &s,
                             &loaded_d,
                             digest,
                             sizeof(digest),
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "ECDSA sign failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }
    check.ecdsa_sign = true;

    ESP_LOGI(TAG, "verify PASS check with MakeCredential public key");
    if (!import_public_key(&group, public_key, &verify_point)) {
        goto cleanup;
    }

    ret = mbedtls_ecdsa_verify(&group,
                               digest,
                               sizeof(digest),
                               &verify_point,
                               &r,
                               &s);
    if (ret != 0) {
        ESP_LOGE(TAG, "ECDSA verify failed: -0x%04x", (unsigned int)-ret);
        goto cleanup;
    }
    check.verify = true;
    ESP_LOGI(TAG, "verify PASS");

cleanup:
    log_summary(&check);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&loaded_d);
    mbedtls_mpi_free(&private_d);
    mbedtls_ecp_point_free(&verify_point);
    mbedtls_ecp_point_free(&public_point);
    mbedtls_ecp_group_free(&group);
    memset(&loaded, 0, sizeof(loaded));
    memset(private_key_after_reboot, 0, sizeof(private_key_after_reboot));
    memset(digest, 0, sizeof(digest));
}

static void test_fido_storage_loop_task(void *arg)
{
    TaskHandle_t caller = (TaskHandle_t)arg;

    test_fido_storage_loop_run();
    if (caller != NULL) {
        xTaskNotifyGive(caller);
    }
    vTaskDelete(NULL);
}

void test_fido_storage_loop(void)
{
    TaskHandle_t caller = xTaskGetCurrentTaskHandle();
    TaskHandle_t task = NULL;
    BaseType_t ok = xTaskCreate(test_fido_storage_loop_task,
                                "fido_loop_test",
                                24576,
                                caller,
                                5,
                                &task);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "failed to create FIDO storage loop test task");
        return;
    }

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
}
