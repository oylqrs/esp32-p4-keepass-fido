#include "FT6336.h"

#include <string.h>

#include "driver/i2c.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ft6336";

#define FT6336_REG_TD_STATUS     0x02
#define FT6336_REG_P1_XH         0x03
#define FT6336_REG_CHIP_ID       0xA3
#define FT6336_REG_VENDOR_ID     0xA8
#define FT6336_REG_G_MODE        0xA4

#define FT6336_TOUCH_COUNT_MASK  0x0F
#define FT6336_TOUCH_EVENT_MASK  0xC0
#define FT6336_TOUCH_ID_MASK     0xF0

static bool s_i2c_installed;

static esp_err_t ft6336_read_regs(uint8_t reg, uint8_t *data, size_t len)
{
    return i2c_master_write_read_device(FT6336_I2C_PORT,
                                        FT6336_I2C_ADDR,
                                        &reg,
                                        1,
                                        data,
                                        len,
                                        pdMS_TO_TICKS(100));
}

static esp_err_t ft6336_write_reg(uint8_t reg, uint8_t value)
{
    uint8_t data[2] = {reg, value};
    return i2c_master_write_to_device(FT6336_I2C_PORT,
                                      FT6336_I2C_ADDR,
                                      data,
                                      sizeof(data),
                                      pdMS_TO_TICKS(100));
}

esp_err_t ft6336_init(void)
{
    if (!s_i2c_installed) {
        const i2c_config_t i2c_config = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = FT6336_I2C_SDA_GPIO,
            .scl_io_num = FT6336_I2C_SCL_GPIO,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master.clk_speed = FT6336_I2C_FREQ_HZ,
            .clk_flags = 0,
        };
        ESP_RETURN_ON_ERROR(i2c_param_config(FT6336_I2C_PORT, &i2c_config), TAG, "config i2c failed");
        ESP_RETURN_ON_ERROR(i2c_driver_install(FT6336_I2C_PORT, I2C_MODE_MASTER, 0, 0, 0), TAG, "install i2c failed");
        s_i2c_installed = true;
    }

#if FT6336_RST_GPIO >= 0
    const gpio_config_t reset_config = {
        .pin_bit_mask = 1ULL << FT6336_RST_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&reset_config), TAG, "config reset gpio failed");
    gpio_set_level(FT6336_RST_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(FT6336_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
#endif

#if FT6336_INT_GPIO >= 0
    const gpio_config_t int_config = {
        .pin_bit_mask = 1ULL << FT6336_INT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&int_config), TAG, "config int gpio failed");
#endif

    uint8_t chip_id = 0;
    esp_err_t ret = ft6336_read_regs(FT6336_REG_CHIP_ID, &chip_id, 1);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "FT6336 not responding at 0x%02X, check SDA=%d SCL=%d: %s",
                 FT6336_I2C_ADDR, FT6336_I2C_SDA_GPIO, FT6336_I2C_SCL_GPIO, esp_err_to_name(ret));
        return ret;
    }

    uint8_t vendor_id = 0;
    (void)ft6336_read_regs(FT6336_REG_VENDOR_ID, &vendor_id, 1);
    ESP_LOGI(TAG, "FT6336 detected, chip_id=0x%02X vendor_id=0x%02X", chip_id, vendor_id);

    // 0x00: polling mode. Coordinates are read periodically by the app task.
    (void)ft6336_write_reg(FT6336_REG_G_MODE, 0x00);
    return ESP_OK;
}

esp_err_t ft6336_read_point(ft6336_point_t *point, uint8_t *point_count)
{
    if (!point || !point_count) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t count = 0;
    esp_err_t ret = ft6336_read_regs(FT6336_REG_TD_STATUS, &count, 1);
    if (ret != ESP_OK) {
        return ret;
    }

    count &= FT6336_TOUCH_COUNT_MASK;
    if (count == 0 || count > 2) {
        *point_count = 0;
        memset(point, 0, sizeof(*point));
        return ESP_OK;
    }

    uint8_t data[4] = {0};
    ret = ft6336_read_regs(FT6336_REG_P1_XH, data, sizeof(data));
    if (ret != ESP_OK) {
        return ret;
    }

    point->event = (data[0] & FT6336_TOUCH_EVENT_MASK) >> 6;
    point->x = ((uint16_t)(data[0] & 0x0F) << 8) | data[1];
    point->id = (data[2] & FT6336_TOUCH_ID_MASK) >> 4;
    point->y = ((uint16_t)(data[2] & 0x0F) << 8) | data[3];
    *point_count = count;

    return ESP_OK;
}
