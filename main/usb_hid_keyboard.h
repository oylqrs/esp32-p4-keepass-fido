#pragma once

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t usb_hid_keyboard_init(void);
esp_err_t usb_hid_keyboard_type_text(const char *text);
bool usb_hid_keyboard_is_ready(void);
esp_err_t usb_msc_storage_init(void);
esp_err_t usb_hid_mount_usbstore_app(void);
esp_err_t usb_hid_dump_storage_files(void);
esp_err_t usb_hid_toggle_usbstore(void);

#ifdef __cplusplus
}
#endif
