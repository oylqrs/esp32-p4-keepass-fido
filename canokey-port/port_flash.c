#include <string.h>

#include "canokey_esp32p4.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "fs.h"
#include "lfs.h"
#include "platform-config.h"

#define CANOKEY_LFS_PARTITION_LABEL "canokey_lfs"
#define CANOKEY_LFS_BLOCK_SIZE      4096
#define CANOKEY_LFS_READ_SIZE       16
#define CANOKEY_LFS_PROG_SIZE       256
#define CANOKEY_LFS_CACHE_SIZE      256
#define CANOKEY_LFS_LOOKAHEAD_SIZE  16

static uint8_t s_platform_config_page[PLATFORM_CONFIG_PAGE_SIZE];
static bool s_platform_config_page_ready;
static const esp_partition_t *s_lfs_partition;
static uint8_t s_lfs_read_buffer[CANOKEY_LFS_CACHE_SIZE];
static uint8_t s_lfs_prog_buffer[CANOKEY_LFS_CACHE_SIZE];
static uint8_t s_lfs_lookahead_buffer[CANOKEY_LFS_LOOKAHEAD_SIZE];
static bool s_lfs_mounted;

static const char *TAG = "canokey_flash";

static esp_err_t ensure_lfs_partition(void)
{
    if (!s_lfs_partition) {
        s_lfs_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                   ESP_PARTITION_SUBTYPE_ANY,
                                                   CANOKEY_LFS_PARTITION_LABEL);
    }
    if (!s_lfs_partition) {
        ESP_LOGE(TAG, "LittleFS partition '%s' not found", CANOKEY_LFS_PARTITION_LABEL);
        return ESP_ERR_NOT_FOUND;
    }
    return ESP_OK;
}

static size_t platform_config_flash_offset(void)
{
    return s_lfs_partition->size - CANOKEY_LFS_BLOCK_SIZE;
}

static int lfs_from_esp_err(esp_err_t err)
{
    return err == ESP_OK ? 0 : LFS_ERR_IO;
}

static int canokey_lfs_read(const struct lfs_config *cfg,
                            lfs_block_t block,
                            lfs_off_t off,
                            void *buffer,
                            lfs_size_t size)
{
    (void)cfg;
    if (!s_lfs_partition) {
        return LFS_ERR_IO;
    }

    return lfs_from_esp_err(esp_partition_read(s_lfs_partition,
                                               (size_t)block * CANOKEY_LFS_BLOCK_SIZE + off,
                                               buffer,
                                               size));
}

static int canokey_lfs_prog(const struct lfs_config *cfg,
                            lfs_block_t block,
                            lfs_off_t off,
                            const void *buffer,
                            lfs_size_t size)
{
    (void)cfg;
    if (!s_lfs_partition) {
        return LFS_ERR_IO;
    }

    return lfs_from_esp_err(esp_partition_write(s_lfs_partition,
                                                (size_t)block * CANOKEY_LFS_BLOCK_SIZE + off,
                                                buffer,
                                                size));
}

static int canokey_lfs_erase(const struct lfs_config *cfg, lfs_block_t block)
{
    (void)cfg;
    if (!s_lfs_partition) {
        return LFS_ERR_IO;
    }

    return lfs_from_esp_err(esp_partition_erase_range(s_lfs_partition,
                                                      (size_t)block * CANOKEY_LFS_BLOCK_SIZE,
                                                      CANOKEY_LFS_BLOCK_SIZE));
}

static int canokey_lfs_sync(const struct lfs_config *cfg)
{
    (void)cfg;
    return 0;
}

static struct lfs_config s_lfs_config = {
    .read = canokey_lfs_read,
    .prog = canokey_lfs_prog,
    .erase = canokey_lfs_erase,
    .sync = canokey_lfs_sync,
    .read_size = CANOKEY_LFS_READ_SIZE,
    .prog_size = CANOKEY_LFS_PROG_SIZE,
    .block_size = CANOKEY_LFS_BLOCK_SIZE,
    .cache_size = CANOKEY_LFS_CACHE_SIZE,
    .lookahead_size = CANOKEY_LFS_LOOKAHEAD_SIZE,
    .block_cycles = 500,
    .read_buffer = s_lfs_read_buffer,
    .prog_buffer = s_lfs_prog_buffer,
    .lookahead_buffer = s_lfs_lookahead_buffer,
};

static void ensure_platform_config_page(void)
{
    if (!s_platform_config_page_ready) {
        memset(s_platform_config_page, 0xFF, sizeof(s_platform_config_page));
        if (ensure_lfs_partition() == ESP_OK) {
            esp_err_t ret = esp_partition_read(s_lfs_partition,
                                               platform_config_flash_offset(),
                                               s_platform_config_page,
                                               sizeof(s_platform_config_page));
            if (ret == ESP_OK) {
                ESP_LOGI(TAG,
                         "Platform config loaded from flash offset=0x%lx len=%u",
                         (unsigned long)(s_lfs_partition->address + platform_config_flash_offset()),
                         (unsigned)sizeof(s_platform_config_page));
            } else {
                ESP_LOGW(TAG,
                         "Platform config flash read failed: %s",
                         esp_err_to_name(ret));
            }
        }
        s_platform_config_page_ready = true;
    }
}

int platform_config_page_read(size_t off, void *buf, size_t len)
{
    ensure_platform_config_page();
    if (!buf || off > PLATFORM_CONFIG_PAGE_SIZE || len > PLATFORM_CONFIG_PAGE_SIZE - off) {
        return -1;
    }

    memcpy(buf, s_platform_config_page + off, len);
    return 0;
}

int platform_config_page_write(const void *page, size_t len)
{
    ensure_platform_config_page();
    if (!page || len != PLATFORM_CONFIG_PAGE_SIZE) {
        return -1;
    }

    memcpy(s_platform_config_page, page, PLATFORM_CONFIG_PAGE_SIZE);
    if (ensure_lfs_partition() != ESP_OK) {
        return -1;
    }

    esp_err_t ret = esp_partition_erase_range(s_lfs_partition,
                                              platform_config_flash_offset(),
                                              CANOKEY_LFS_BLOCK_SIZE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Platform config flash erase failed: %s", esp_err_to_name(ret));
        return -1;
    }

    ret = esp_partition_write(s_lfs_partition,
                              platform_config_flash_offset(),
                              s_platform_config_page,
                              sizeof(s_platform_config_page));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Platform config flash write failed: %s", esp_err_to_name(ret));
        return -1;
    }

    ESP_LOGW(TAG,
             "Platform config saved to flash offset=0x%lx len=%u",
             (unsigned long)(s_lfs_partition->address + platform_config_flash_offset()),
             (unsigned)sizeof(s_platform_config_page));
    return 0;
}

esp_err_t canokey_esp32p4_flash_init(void)
{
    if (s_lfs_mounted) {
        return ESP_OK;
    }

    esp_err_t partition_ret = ensure_lfs_partition();
    if (partition_ret != ESP_OK) {
        return partition_ret;
    }

    s_lfs_config.block_count = s_lfs_partition->size / CANOKEY_LFS_BLOCK_SIZE - 1;
    if (s_lfs_config.block_count < 8) {
        ESP_LOGE(TAG, "LittleFS partition too small: %u blocks", (unsigned int)s_lfs_config.block_count);
        return ESP_ERR_INVALID_SIZE;
    }

    int err = fs_mount(&s_lfs_config);
    if (err == 0) {
        s_lfs_mounted = true;
        ESP_LOGI(TAG, "CanoKey LittleFS mounted: label=%s offset=0x%lx size=%lu blocks=%u",
                 s_lfs_partition->label,
                 (unsigned long)s_lfs_partition->address,
                 (unsigned long)s_lfs_partition->size,
                 (unsigned int)s_lfs_config.block_count);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "CanoKey LittleFS mount failed (%d), formatting", err);
    err = fs_format(&s_lfs_config);
    if (err != 0) {
        ESP_LOGE(TAG, "CanoKey LittleFS format failed: %d", err);
        return ESP_FAIL;
    }

    err = fs_mount(&s_lfs_config);
    if (err != 0) {
        ESP_LOGE(TAG, "CanoKey LittleFS mount after format failed: %d", err);
        return ESP_FAIL;
    }

    s_lfs_mounted = true;
    ESP_LOGI(TAG, "CanoKey LittleFS formatted and mounted: label=%s offset=0x%lx size=%lu blocks=%u",
             s_lfs_partition->label,
             (unsigned long)s_lfs_partition->address,
             (unsigned long)s_lfs_partition->size,
             (unsigned int)s_lfs_config.block_count);
    return ESP_OK;
}
