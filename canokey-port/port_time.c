#include <stdint.h>

#include "device.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static esp_timer_handle_t s_timeout_timer;
static void (*s_timeout_callback)(void);

static void timeout_timer_cb(void *arg)
{
    (void)arg;
    if (s_timeout_callback) {
        s_timeout_callback();
    }
}

void device_delay(int ms)
{
    if (ms <= 0) {
        taskYIELD();
        return;
    }

    vTaskDelay(pdMS_TO_TICKS(ms));
}

uint32_t device_get_tick(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

void device_set_timeout(void (*callback)(void), uint16_t timeout)
{
    s_timeout_callback = callback;

    if (!s_timeout_timer) {
        const esp_timer_create_args_t args = {
            .callback = timeout_timer_cb,
            .name = "canokey_timeout",
        };
        if (esp_timer_create(&args, &s_timeout_timer) != ESP_OK) {
            return;
        }
    }

    esp_timer_stop(s_timeout_timer);
    if (callback && timeout > 0) {
        esp_timer_start_once(s_timeout_timer, (uint64_t)timeout * 1000ULL);
    }
}
