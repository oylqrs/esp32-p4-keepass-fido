/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdint.h>
#include <stddef.h>

#include "credential_test.h"
#include "FT6336.h"
#include "canokey_esp32p4.h"
#include "lcd/lcd_driver.h"
#include "test_ctap_makecredential.h"
#include "test_fido_storage_loop.h"
#include "test_aes.h"
#include "test_ecdsa_sign.h"
#include "test_ecdsa_verify.h"
#include "test_ecc.h"
#include "test_hmac_sha256.h"
#include "test_public_key_verify.h"
#include "test_random.h"
#include "test_sha256.h"
#include "ui/UI_SCREEN1.h"
#include "ui/ui_fido_confirm.h"
#include "usb_hid_keyboard.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_ops.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"

static const char *TAG = "app";

#define LVGL_TICK_PERIOD_MS             2
#define LVGL_DRAW_BUF_LINES             40

typedef struct {
    esp_lcd_panel_handle_t panel;
    lv_display_t *display;
} lvgl_port_display_t;



static void lvgl_tick_cb(void *arg)
{
    (void)arg;
    lv_tick_inc(LVGL_TICK_PERIOD_MS);
}

static void lvgl_flush_cb(lv_display_t *display, const lv_area_t *area, uint8_t *px_map)
{
    lvgl_port_display_t *port_display = lv_display_get_user_data(display);
    if (!port_display || !port_display->panel) {
        lv_display_flush_ready(display);
        return;
    }

    esp_err_t ret = esp_lcd_panel_draw_bitmap(port_display->panel,
                                              area->x1,
                                              area->y1,
                                              area->x2 + 1,
                                              area->y2 + 1,
                                              px_map);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "LVGL flush failed: %s", esp_err_to_name(ret));
    }

    lv_display_flush_ready(display);
}

static void lvgl_touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data)
{
    (void)indev;

    static uint16_t last_x;
    static uint16_t last_y;
    static bool was_pressed;

    ft6336_point_t point = {0};
    uint8_t point_count = 0;
    esp_err_t ret = ft6336_read_point(&point, &point_count);
    if (ret == ESP_OK && point_count > 0) {
        if (point.x >= LCD_H_RES) {
            point.x = LCD_H_RES - 1;
        }
        if (point.y >= LCD_V_RES) {
            point.y = LCD_V_RES - 1;
        }

        data->state = LV_INDEV_STATE_PRESSED;
        data->point.x = point.x;
        data->point.y = point.y;

        if (!was_pressed || point.x != last_x || point.y != last_y) {
            ESP_LOGI("touch", "touch count=%u id=%u event=%u x=%u y=%u",
                     point_count, point.id, point.event, point.x, point.y);
        }

        last_x = point.x;
        last_y = point.y;
        was_pressed = true;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
        data->point.x = last_x;
        data->point.y = last_y;

        if (was_pressed) {
            ESP_LOGI("touch", "release");
        }
        was_pressed = false;
    }
}

static void lvgl_task(void *arg)
{
    (void)arg;
    while (true) {
        uint32_t delay_ms = lv_timer_handler();
        if (delay_ms < 5) {
            delay_ms = 5;
        } else if (delay_ms > 20) {
            delay_ms = 20;
        }
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

static void lvgl_port_start(esp_lcd_panel_handle_t panel, bool touch_enabled)
{
    lv_init();

    static lvgl_port_display_t port_display = {0};
    port_display.panel = panel;

    lv_display_t *display = lv_display_create(LCD_H_RES, LCD_V_RES);
    port_display.display = display;
    lv_display_set_user_data(display, &port_display);
    lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
    lv_display_set_flush_cb(display, lvgl_flush_cb);

    const size_t draw_buf_size = LCD_H_RES * LVGL_DRAW_BUF_LINES * LCD_BYTES_PER_PIXEL;
    void *draw_buf_1 = heap_caps_malloc(draw_buf_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT | MALLOC_CAP_DMA);
    void *draw_buf_2 = heap_caps_malloc(draw_buf_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT | MALLOC_CAP_DMA);
    ESP_ERROR_CHECK((draw_buf_1 && draw_buf_2) ? ESP_OK : ESP_ERR_NO_MEM);
    lv_display_set_buffers(display, draw_buf_1, draw_buf_2, draw_buf_size, LV_DISPLAY_RENDER_MODE_PARTIAL);

    if (touch_enabled) {
        lv_indev_t *indev = lv_indev_create();
        lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
        lv_indev_set_read_cb(indev, lvgl_touch_read_cb);
        lv_indev_set_display(indev, display);
    }

    const esp_timer_create_args_t tick_timer_args = {
        .callback = lvgl_tick_cb,
        .name = "lvgl_tick",
    };
    esp_timer_handle_t tick_timer = NULL;
    ESP_ERROR_CHECK(esp_timer_create(&tick_timer_args, &tick_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(tick_timer, LVGL_TICK_PERIOD_MS * 1000));

    ui_screen1_show();
    xTaskCreate(lvgl_task, "lvgl", 8192, NULL, 4, NULL);
}

void app_main(void)
{
    
    canokey_esp32p4_crypto_init();
     esp_err_t hid_ret = usb_hid_keyboard_init();
    if (hid_ret != ESP_OK) {
        ESP_LOGW(TAG, "USB HID init failed: %s", esp_err_to_name(hid_ret));
    } 
    
    esp_err_t msc_ret = usb_msc_storage_init();
    if (msc_ret != ESP_OK) {
        ESP_LOGW(TAG, "USB MSC storage init failed: %s", esp_err_to_name(msc_ret));
    }


    else if (msc_ret == ESP_OK) {
        esp_err_t usbstore_ret = usb_hid_mount_usbstore_app();
        if (usbstore_ret != ESP_OK) {
            ESP_LOGW(TAG, "USB disk default APP mount failed: %s", esp_err_to_name(usbstore_ret));
        }
    }



   // test_sha256();
    //test_hmac_sha256();
   // test_aes();
    //test_random();
    //test_ecc();
   // test_public_key_verify();
   // test_ecdsa_sign();
   // test_ecdsa_verify();
   // test_ctap_makecredential();
    //credential_test();
   // test_fido_storage_loop();
  //  canokey_esp32p4_crypto_selftest();

    esp_lcd_panel_handle_t dpi_panel = lcd_driver_init();

    esp_err_t touch_ret = ft6336_init();
    bool touch_enabled = touch_ret == ESP_OK;
    if (!touch_enabled) {
        ESP_LOGW(TAG, "Touch init failed: %s", esp_err_to_name(touch_ret));
    }

    ESP_LOGI(TAG, "Start LVGL");
    lvgl_port_start(dpi_panel, touch_enabled);

    ui_fido_confirm_init();
    
    //
    //暂时关闭fido2
    //esp_err_t canokey_ret = canokey_esp32p4_start();
   /* if (canokey_ret != ESP_OK) {
        ESP_LOGW(TAG, "CanoKey init failed: %s", esp_err_to_name(canokey_ret));
    }*/

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
