#include "credential_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "canokey_esp32p4.h"
#include "esp_err.h"
#include "esp_log.h"
#include "fs.h"

#define FIDO_CREDENTIAL_DB_FILE "credential.db"
#define FIDO_CREDENTIAL_ID_LEN  32
#define FIDO_PRIVATE_KEY_LEN    32
#define FIDO_RP_ID_MAX_LEN      128
#define FIDO_USER_ID_MAX_LEN    64
#define FIDO_USER_NAME_MAX_LEN  64

static const char *TAG = "fido_credential_test";

typedef struct {
    uint8_t credential_id[FIDO_CREDENTIAL_ID_LEN];
    uint16_t credential_id_len;
    uint8_t private_key[FIDO_PRIVATE_KEY_LEN];
    char rp_id[FIDO_RP_ID_MAX_LEN];
    uint8_t user_id[FIDO_USER_ID_MAX_LEN];
    uint16_t user_id_len;
    char user_name[FIDO_USER_NAME_MAX_LEN];
    uint32_t sign_count;
} fido_credential_t;

static bool storage_save_credential(const fido_credential_t *cred)
{
    if (cred == NULL) {
        return false;
    }

    int ret = write_file(FIDO_CREDENTIAL_DB_FILE, cred, 0, sizeof(*cred), 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "save credential failed: %d", ret);
        return false;
    }

    return true;
}

static bool storage_add(const fido_credential_t *cred)
{
    if (cred == NULL) {
        return false;
    }

    int ret = append_file(FIDO_CREDENTIAL_DB_FILE, cred, sizeof(*cred));
    if (ret != 0) {
        ESP_LOGE(TAG, "add credential failed: %d", ret);
        return false;
    }

    return true;
}

static bool storage_clear(void)
{
    int ret = write_file(FIDO_CREDENTIAL_DB_FILE, NULL, 0, 0, 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "clear credential db failed: %d", ret);
        return false;
    }

    return true;
}

static bool storage_load_credential(const uint8_t *credential_id,
                                    uint16_t credential_id_len,
                                    fido_credential_t *cred)
{
    if (credential_id == NULL || cred == NULL || credential_id_len == 0) {
        return false;
    }

    int ret = read_file(FIDO_CREDENTIAL_DB_FILE, cred, 0, sizeof(*cred));
    if (ret != sizeof(*cred)) {
        ESP_LOGE(TAG, "load credential failed: %d", ret);
        return false;
    }

    if (cred->credential_id_len != credential_id_len ||
        memcmp(cred->credential_id, credential_id, credential_id_len) != 0) {
        ESP_LOGE(TAG, "loaded credential id mismatch");
        return false;
    }

    return true;
}

static bool storage_find_by_rp(const char *rp_id, fido_credential_t *cred)
{
    if (rp_id == NULL || cred == NULL) {
        return false;
    }

    int file_size = get_file_size(FIDO_CREDENTIAL_DB_FILE);
    int record_size = (int)sizeof(*cred);
    if (file_size <= 0 || (file_size % record_size) != 0) {
        ESP_LOGE(TAG, "invalid credential db size: %d", file_size);
        return false;
    }

    int credential_count = file_size / record_size;
    for (int i = 0; i < credential_count; ++i) {
        int ret = read_file(FIDO_CREDENTIAL_DB_FILE,
                            cred,
                            i * record_size,
                            sizeof(*cred));
        if (ret != sizeof(*cred)) {
            ESP_LOGE(TAG, "read credential %d failed: %d", i, ret);
            return false;
        }

        if (strcmp(cred->rp_id, rp_id) == 0) {
            return true;
        }
    }

    return false;
}

static void fill_fake_credential(fido_credential_t *cred,
                                 uint8_t seed,
                                 const char *rp_id,
                                 const char *user_name)
{
    memset(cred, 0, sizeof(*cred));

    for (uint8_t i = 0; i < FIDO_CREDENTIAL_ID_LEN; ++i) {
        cred->credential_id[i] = (uint8_t)(seed + i);
        cred->private_key[i] = (uint8_t)(0xA0 + seed + i);
    }
    cred->credential_id_len = FIDO_CREDENTIAL_ID_LEN;

    cred->user_id[0] = seed;
    cred->user_id[1] = (uint8_t)(seed + 1);
    cred->user_id[2] = (uint8_t)(seed + 2);
    cred->user_id_len = 3;

    snprintf(cred->rp_id, sizeof(cred->rp_id), "%s", rp_id);
    snprintf(cred->user_name, sizeof(cred->user_name), "%s", user_name);
    cred->sign_count = 0;
}

void credential_test(void)
{
    fido_credential_t cred1;
    fido_credential_t cred2;
    fido_credential_t google_credential;
    fido_credential_t github_credential;
    fido_credential_t microsoft_credential;
    fido_credential_t found_credential;

    ESP_LOGI(TAG, "[FIDO STORAGE] start credential storage test");

    esp_err_t flash_ret = canokey_esp32p4_flash_init();
    if (flash_ret != ESP_OK) {
        ESP_LOGE(TAG, "LittleFS init failed: %s", esp_err_to_name(flash_ret));
        return;
    }

    fill_fake_credential(&cred1, 0x01, "example.com", "test");
    memset(&cred2, 0, sizeof(cred2));

    ESP_LOGI(TAG, "save credential");
    ESP_LOGI(TAG, "id:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, cred1.credential_id, cred1.credential_id_len, ESP_LOG_INFO);

    if (!storage_save_credential(&cred1)) {
        ESP_LOGE(TAG, "STORAGE FAIL");
        return;
    }

    ESP_LOGI(TAG, "load credential");
    if (!storage_load_credential(cred1.credential_id, cred1.credential_id_len, &cred2)) {
        ESP_LOGE(TAG, "STORAGE FAIL");
        return;
    }

    ESP_LOGI(TAG, "compare:");
    if (memcmp(&cred1, &cred2, sizeof(cred1)) == 0) {
        ESP_LOGI(TAG, "PASS");
        ESP_LOGI(TAG, "STORAGE PASS");
    } else {
        ESP_LOGE(TAG, "FAIL");
        ESP_LOGE(TAG, "STORAGE FAIL");
        ESP_LOGI(TAG, "expected:");
        ESP_LOG_BUFFER_HEXDUMP(TAG, (const uint8_t *)&cred1, sizeof(cred1), ESP_LOG_INFO);
        ESP_LOGI(TAG, "actual:");
        ESP_LOG_BUFFER_HEXDUMP(TAG, (const uint8_t *)&cred2, sizeof(cred2), ESP_LOG_INFO);
    }

    memset(&cred1, 0, sizeof(cred1));
    memset(&cred2, 0, sizeof(cred2));

    ESP_LOGI(TAG, "[FIDO STORAGE] start multi credential test");
    if (!storage_clear()) {
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        return;
    }

    fill_fake_credential(&google_credential, 0x10, "google.com", "google-user");
    fill_fake_credential(&github_credential, 0x20, "github.com", "github-user");
    fill_fake_credential(&microsoft_credential, 0x30, "microsoft.com", "microsoft-user");
    memset(&found_credential, 0, sizeof(found_credential));

    ESP_LOGI(TAG, "storage_add google.com");
    if (!storage_add(&google_credential)) {
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        return;
    }

    ESP_LOGI(TAG, "storage_add github.com");
    if (!storage_add(&github_credential)) {
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        return;
    }

    ESP_LOGI(TAG, "storage_add microsoft.com");
    if (!storage_add(&microsoft_credential)) {
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        return;
    }

    int db_size = get_file_size(FIDO_CREDENTIAL_DB_FILE);
    int expected_db_size = 3 * (int)sizeof(fido_credential_t);
    ESP_LOGI(TAG, "credential.db size: %d", db_size);
    if (db_size != expected_db_size) {
        ESP_LOGE(TAG, "credential.db expected %d bytes", expected_db_size);
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        return;
    }

    ESP_LOGI(TAG, "storage_find_by_rp github.com");
    if (!storage_find_by_rp("github.com", &found_credential)) {
        ESP_LOGE(TAG, "github.com credential not found");
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        return;
    }

    ESP_LOGI(TAG, "compare github credential:");
    if (memcmp(&github_credential, &found_credential, sizeof(github_credential)) == 0) {
        ESP_LOGI(TAG, "PASS");
        ESP_LOGI(TAG, "MULTI STORAGE PASS");
    } else {
        ESP_LOGE(TAG, "FAIL");
        ESP_LOGE(TAG, "MULTI STORAGE FAIL");
        ESP_LOGI(TAG, "expected github credential:");
        ESP_LOG_BUFFER_HEXDUMP(TAG,
                               (const uint8_t *)&github_credential,
                               sizeof(github_credential),
                               ESP_LOG_INFO);
        ESP_LOGI(TAG, "actual credential:");
        ESP_LOG_BUFFER_HEXDUMP(TAG,
                               (const uint8_t *)&found_credential,
                               sizeof(found_credential),
                               ESP_LOG_INFO);
    }
}
