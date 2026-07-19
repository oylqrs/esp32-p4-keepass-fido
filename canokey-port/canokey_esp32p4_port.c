#include "applets.h"
#include "apdu.h"
#include "canokey_esp32p4.h"
#include "device.h"
#include "esp_err.h"
#include "esp_log.h"
#include "fs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static TaskHandle_t s_canokey_task_handle;

static const char *TAG = "canokey_port";

#define CTAP_CERT_FILE_NAME   "ctap_cert"
#define CTAP_PRIVATE_KEY_ATTR 0x00

static esp_err_t ensure_test_attestation_installed(void)
{
    static const uint8_t fido_private_key[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    };
    static const uint8_t cert[] = {
        0x30, 0x03, 0x02, 0x01, 0x01,
    };

    uint8_t key[sizeof(fido_private_key)] = {0};
    int key_len = read_attr(CTAP_CERT_FILE_NAME,
                            CTAP_PRIVATE_KEY_ATTR,
                            key,
                            sizeof(key));
    int cert_len = get_file_size(CTAP_CERT_FILE_NAME);

    if (key_len == (int)sizeof(fido_private_key) && cert_len > 0) {
        ESP_LOGI(TAG, "CTAP attestation already installed: key_len=%d cert_len=%d", key_len, cert_len);
        return ESP_OK;
    }

    ESP_LOGW(TAG,
             "CTAP attestation missing/incomplete: key_len=%d cert_len=%d; installing test attestation",
             key_len,
             cert_len);

    int ret = write_file(CTAP_CERT_FILE_NAME, cert, 0, sizeof(cert), 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "write test attestation certificate failed: %d", ret);
        return ESP_FAIL;
    }

    ret = write_attr(CTAP_CERT_FILE_NAME,
                     CTAP_PRIVATE_KEY_ATTR,
                     fido_private_key,
                     sizeof(fido_private_key));
    if (ret != 0) {
        ESP_LOGE(TAG, "write test attestation private key failed: %d", ret);
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "CTAP test attestation installed");
    return ESP_OK;
}

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking)
{
    do {
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(lock, &expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            return 0;
        }

        if (!blocking) {
            return -1;
        }

        vTaskDelay(1);
    } while (true);
}

void device_spinlock_unlock(volatile uint32_t *lock)
{
    __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update)
{
    return __atomic_compare_exchange_n(var, &expect, update, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED) ? 0 : -1;
}

static void canokey_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "CanoKey task starting");
    ESP_LOGI(TAG, "CanoKey LittleFS mount begin");
    if (canokey_esp32p4_flash_init() != ESP_OK) {
        ESP_LOGE(TAG, "CanoKey task stopped: LittleFS unavailable");
        s_canokey_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "CanoKey LittleFS mount done");
    ESP_LOGI(TAG, "CanoKey crypto port init begin");
    if (canokey_esp32p4_crypto_init() != ESP_OK) {
        ESP_LOGE(TAG, "CanoKey task stopped: crypto port unavailable");
        s_canokey_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    if (canokey_esp32p4_crypto_selftest() != ESP_OK) {
        ESP_LOGE(TAG, "crypto selftest failed");
        s_canokey_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "CanoKey crypto port init done");
    ESP_LOGI(TAG, "CanoKey APDU buffer init begin");
    init_apdu_buffer();
    ESP_LOGI(TAG, "CanoKey APDU buffer init done");
    ESP_LOGI(TAG, "CanoKey device_init begin");
    device_init();
    ESP_LOGI(TAG, "CanoKey device_init done");
    ESP_LOGI(TAG, "CanoKey applets_install begin");
    if (applets_install() != 0) {
        ESP_LOGE(TAG, "CanoKey task stopped: applets_install failed");
        s_canokey_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "CanoKey applets_install done");

    if (ensure_test_attestation_installed() != ESP_OK) {
        ESP_LOGE(TAG, "CanoKey task stopped: CTAP attestation unavailable");
        s_canokey_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    while (true) {
        ESP_LOGD(TAG, "CanoKey device_loop begin");
        device_loop();
        ESP_LOGD(TAG, "CanoKey device_loop done");
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

esp_err_t canokey_esp32p4_start(void)
{
    if (s_canokey_task_handle) {
        return ESP_OK;
    }

    BaseType_t ok = xTaskCreate(canokey_task,
                                "canokey",
                                12288,
                                NULL,
                                5,
                                &s_canokey_task_handle);
    if (ok != pdPASS) {
        s_canokey_task_handle = NULL;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

bool canokey_esp32p4_is_running(void)
{
    return s_canokey_task_handle != NULL;
}
