#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

esp_err_t canokey_esp32p4_start(void);
bool canokey_esp32p4_is_running(void);
void canokey_esp32p4_set_user_presence_request_callback(void (*callback)(uint8_t entry));
uint8_t canokey_esp32p4_get_current_ctap_cbor_cmd(void);
esp_err_t canokey_esp32p4_crypto_init(void);
esp_err_t canokey_esp32p4_crypto_selftest(void);
esp_err_t canokey_esp32p4_flash_init(void);
void canokey_esp32p4_ctaphid_usb_init(void);
uint8_t canokey_esp32p4_ctaphid_queue_out_report(const uint8_t *report, uint16_t len);
uint8_t canokey_esp32p4_ctaphid_queue_data_in(void);
