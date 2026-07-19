#include "test_random.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "esp_log.h"
#include "rand.h"

static const char *TAG = "crypto_test_random";

static void dump_hex(const char *label, const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "%s:", label);
    ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_INFO);
}

static bool all_zero(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

void test_random(void)
{
    uint8_t buf_a[32];
    uint8_t buf_b[32];
    ESP_LOGI(TAG, "start random test");

    uint32_t r0 = random32();
    uint32_t r1 = random32();
    ESP_LOGI(TAG, "random32: 0x%08" PRIx32 ", 0x%08" PRIx32, r0, r1);

    if (r0 == 0 && r1 == 0) {
        ESP_LOGE(TAG, "random32 produced two zero values");
        return;
    }

    if (r0 == r1) {
        ESP_LOGE(TAG, "two random32 outputs are identical");
        return;
    }

    random_buffer(buf_a, sizeof(buf_a));
    random_buffer(buf_b, sizeof(buf_b));
    dump_hex("random_buffer #1", buf_a, sizeof(buf_a));
    dump_hex("random_buffer #2", buf_b, sizeof(buf_b));

    if (all_zero(buf_a, sizeof(buf_a)) || all_zero(buf_b, sizeof(buf_b))) {
        ESP_LOGE(TAG, "random_buffer produced all-zero data");
        return;
    }

    if (memcmp(buf_a, buf_b, sizeof(buf_a)) == 0) {
        ESP_LOGE(TAG, "two random_buffer outputs are identical");
        return;
    }

    ESP_LOGI(TAG, "port_random OK");
}
