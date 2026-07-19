#include "kdbx_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "kdbx";

static const char *header_field_name(uint8_t field_id)
{
    switch (field_id) {
    case 0:
        return "EndOfHeader";
    case 2:
        return "CipherID";
    case 3:
        return "CompressionFlags";
    case 4:
        return "MasterSeed";
    case 7:
        return "EncryptionIV";
    case 11:
        return "KdfParameters";
    default:
        return "Unknown";
    }
}

static void log_header_field(uint8_t field_id, const uint8_t *data, size_t len, kdbx_header_t *header)
{
    switch (field_id) {
    case 2:
        if (len == sizeof(header->cipher_id)) {
            memcpy(header->cipher_id, data, sizeof(header->cipher_id));
            header->has_cipher_id = true;
        }
        kdbx_log_hex_value(header_field_name(field_id), data, len);
        break;
    case 4:
        if (len == sizeof(header->master_seed)) {
            memcpy(header->master_seed, data, sizeof(header->master_seed));
            header->has_master_seed = true;
        }
        kdbx_log_hex_value(header_field_name(field_id), data, len);
        break;
    case 7:
        if (len == sizeof(header->encryption_iv)) {
            memcpy(header->encryption_iv, data, sizeof(header->encryption_iv));
            header->has_encryption_iv = true;
        }
        kdbx_log_hex_value(header_field_name(field_id), data, len);
        break;
    case 3:
        if (len == 4) {
            header->compression_flags = kdbx_read_le32(data);
            header->has_compression_flags = true;
            ESP_LOGI(TAG, "CompressionFlags value=%lu", (unsigned long)header->compression_flags);
        } else {
            kdbx_log_hex_value(header_field_name(field_id), data, len);
        }
        break;
    case 11:
        kdbx_parse_kdf_parameters(data, len, header);
        break;
    default:
        break;
    }
}

esp_err_t kdbx_parse_file(const char *path,
                          const char *password,
                          kdbx_entry_t *entries,
                          size_t *entry_count,
                          size_t max_entries)
{
    int64_t total_start_us = kdbx_now_us();
    int64_t step_start_us = kdbx_now_us();
    kdbx_header_t header = {0};
    FILE *f = fopen(path, "rb");
    if (!f) {
        ESP_LOGW(TAG, "Failed to open KDBX %s: errno=%d", path, errno);
        kdbx_log_elapsed("open KDBX file failed", total_start_us);
        return ESP_ERR_NOT_FOUND;
    }
    kdbx_log_elapsed("open KDBX file", step_start_us);

    step_start_us = kdbx_now_us();
    uint8_t fixed[12];
    if (fread(fixed, 1, sizeof(fixed), f) != sizeof(fixed)) {
        ESP_LOGW(TAG, "KDBX header too short: %s", path);
        fclose(f);
        kdbx_log_elapsed("read fixed KDBX header failed", total_start_us);
        return ESP_ERR_INVALID_SIZE;
    }

    uint32_t sig1 = kdbx_read_le32(&fixed[0]);
    uint32_t sig2 = kdbx_read_le32(&fixed[4]);
    uint32_t version = kdbx_read_le32(&fixed[8]);
    uint16_t minor = version & 0xffff;
    uint16_t major = version >> 16;

    if (sig1 != 0x9AA2D903 || sig2 != 0xB54BFB67) {
        ESP_LOGW(TAG, "Invalid KDBX signature: sig1=0x%08lx sig2=0x%08lx",
                 (unsigned long)sig1,
                 (unsigned long)sig2);
        fclose(f);
        kdbx_log_elapsed("read fixed KDBX header invalid signature", total_start_us);
        return ESP_ERR_INVALID_RESPONSE;
    }

    if (major != 4 || minor > 1) {
        ESP_LOGW(TAG, "Unsupported KDBX version: major=%u minor=%u", major, minor);
        fclose(f);
        kdbx_log_elapsed("read fixed KDBX header unsupported version", total_start_us);
        return ESP_ERR_NOT_SUPPORTED;
    }
    kdbx_log_elapsed("read fixed KDBX header", step_start_us);

    ESP_LOGI(TAG, "KDBX 4.%u header OK: %s password_len=%u",
             minor,
             path,
             (unsigned int)strlen(password));

    step_start_us = kdbx_now_us();
    unsigned int field_count = 0;
    for (;;) {
        uint8_t field_id;
        uint8_t size_buf[4];
        if (fread(&field_id, 1, 1, f) != 1 || fread(size_buf, 1, sizeof(size_buf), f) != sizeof(size_buf)) {
            ESP_LOGW(TAG, "Unexpected EOF while reading KDBX header fields");
            fclose(f);
            kdbx_log_elapsed("read KDBX header fields failed", total_start_us);
            return ESP_ERR_INVALID_SIZE;
        }
        field_count++;

        uint32_t field_size = kdbx_read_le32(size_buf);
        ESP_LOGI(TAG, "KDBX header field id=%u (%s) size=%lu",
                 field_id,
                 header_field_name(field_id),
                 (unsigned long)field_size);

        uint8_t *field_data = NULL;
        if (field_size > 0) {
            field_data = malloc(field_size);
            if (!field_data) {
                ESP_LOGW(TAG, "No memory for KDBX header field id=%u size=%lu",
                         field_id,
                         (unsigned long)field_size);
                fclose(f);
                kdbx_log_elapsed("read KDBX header fields failed no memory", total_start_us);
                return ESP_ERR_NO_MEM;
            }

            if (fread(field_data, 1, field_size, f) != field_size) {
                ESP_LOGW(TAG, "Unexpected EOF while reading KDBX header field id=%u", field_id);
                free(field_data);
                fclose(f);
                kdbx_log_elapsed("read KDBX header fields failed EOF", total_start_us);
                return ESP_ERR_INVALID_SIZE;
            }

            log_header_field(field_id, field_data, field_size, &header);
            free(field_data);
        }

        if (field_id == 0) {
            break;
        }

        if (field_size == 0 && ferror(f)) {
            ESP_LOGW(TAG, "Failed to read KDBX header field id=%u", field_id);
            fclose(f);
            kdbx_log_elapsed("read KDBX header fields failed file error", total_start_us);
            return ESP_FAIL;
        }
    }
    ESP_LOGI(TAG, "KDBX timing: header fields count=%u", field_count);
    kdbx_log_elapsed("read/parse KDBX header fields", step_start_us);

    step_start_us = kdbx_now_us();
    long header_len_long = ftell(f);
    if (header_len_long <= 0) {
        fclose(f);
        kdbx_log_elapsed("prepare KDBX header bytes failed ftell", total_start_us);
        return ESP_FAIL;
    }

    size_t header_len = (size_t)header_len_long;
    uint8_t *header_bytes = malloc(header_len);
    if (!header_bytes) {
        fclose(f);
        kdbx_log_elapsed("read KDBX header bytes failed no memory", total_start_us);
        return ESP_ERR_NO_MEM;
    }

    if (fseek(f, 0, SEEK_SET) != 0 || fread(header_bytes, 1, header_len, f) != header_len) {
        ESP_LOGW(TAG, "Failed to read KDBX header bytes for hash calculation");
        free(header_bytes);
        fclose(f);
        kdbx_log_elapsed("read KDBX header bytes failed", total_start_us);
        return ESP_FAIL;
    }

    if (fseek(f, header_len_long, SEEK_SET) != 0) {
        free(header_bytes);
        fclose(f);
        kdbx_log_elapsed("restore KDBX payload seek failed", total_start_us);
        return ESP_FAIL;
    }
    kdbx_log_elapsed("read KDBX header bytes for hash", step_start_us);

    uint8_t master_key[32];
    uint8_t hmac_base_key[64];
    step_start_us = kdbx_now_us();
    esp_err_t ret = kdbx_derive_aes_kdf_master_key(&header, password, master_key, hmac_base_key);
    kdbx_log_elapsed("derive KDBX master keys", step_start_us);
    if (ret != ESP_OK) {
        free(header_bytes);
        fclose(f);
        kdbx_log_elapsed("parse KDBX file total failed KDF", total_start_us);
        return ret;
    }

    step_start_us = kdbx_now_us();
    ret = kdbx_decrypt_payload(f,
                               &header,
                               master_key,
                               hmac_base_key,
                               header_bytes,
                               header_len,
                               entries,
                               entry_count,
                               max_entries);
    kdbx_log_elapsed("decrypt/parse KDBX payload", step_start_us);
    free(header_bytes);
    fclose(f);
    if (ret != ESP_OK) {
        kdbx_log_elapsed("parse KDBX file total failed payload", total_start_us);
        return ret;
    }

    ESP_LOGI(TAG, "KDBX payload decrypt and entry parse completed");
    kdbx_log_elapsed("parse KDBX file total", total_start_us);
    return ESP_OK;
}
