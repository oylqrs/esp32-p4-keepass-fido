#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char title[96];
    char username[96];
    char url[128];
    char password[128];
    bool password_protected;
} kdbx_entry_t;

esp_err_t kdbx_load_first_database_from_data(void);
size_t kdbx_get_entry_count(void);
const kdbx_entry_t *kdbx_get_entry(size_t index);

#ifdef __cplusplus
}
#endif
