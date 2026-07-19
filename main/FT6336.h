#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "driver/gpio.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FT6336_I2C_PORT          I2C_NUM_0
#define FT6336_I2C_ADDR          0x38
#define FT6336_I2C_FREQ_HZ       400000

// Change these if your touch panel is wired to other GPIOs.
#define FT6336_I2C_SDA_GPIO      12
#define FT6336_I2C_SCL_GPIO      13
#define FT6336_RST_GPIO          18
#define FT6336_INT_GPIO          7

typedef struct {
    uint16_t x;
    uint16_t y;
    uint8_t id;
    uint8_t event;
} ft6336_point_t;

esp_err_t ft6336_init(void);
esp_err_t ft6336_read_point(ft6336_point_t *point, uint8_t *point_count);

#ifdef __cplusplus
}
#endif
