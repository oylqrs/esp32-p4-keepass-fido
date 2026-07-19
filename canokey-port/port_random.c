#include <string.h>

#include "esp_random.h"
#include "rand.h"

uint32_t random32(void)
{
    return esp_random();
}

void random_buffer(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i += sizeof(uint32_t)) {
        uint32_t value = esp_random();
        size_t copy_len = len - i < sizeof(value) ? len - i : sizeof(value);
        memcpy(buf + i, &value, copy_len);
    }
}
