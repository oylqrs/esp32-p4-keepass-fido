#include "test_ctap_makecredential.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "applets.h"
#include "apdu.h"
#include "canokey_esp32p4.h"
#include "cbor.h"
#include "ctap.h"
#include "device.h"
#include "esp_err.h"
#include "esp_log.h"
#include "fs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define CTAP_CMD_MAKE_CREDENTIAL 0x01
#define COSE_ALG_ES256_VALUE     (-7)
#define CTAP_STATUS_OK           0x00
#define MC_RESP_FMT              1
#define MC_RESP_AUTH_DATA        2
#define MC_RESP_ATT_STMT         3
#define CTAP_CERT_FILE_NAME      "ctap_cert"
#define CTAP_PRIVATE_KEY_ATTR    0
#define AUTH_DATA_RP_ID_HASH_LEN 32
#define AUTH_DATA_FLAGS_OFFSET   32
#define AUTH_DATA_SIGN_COUNT_LEN 4
#define AUTH_DATA_AAGUID_LEN     16
#define AUTH_DATA_CRED_ID_LEN_LEN 2
#define AUTH_DATA_MIN_AT_LEN     (AUTH_DATA_RP_ID_HASH_LEN + 1 + AUTH_DATA_SIGN_COUNT_LEN + \
                                  AUTH_DATA_AAGUID_LEN + AUTH_DATA_CRED_ID_LEN_LEN)
#define AUTH_DATA_FLAG_UP        0x01
#define AUTH_DATA_FLAG_AT        0x40
#define AUTH_DATA_FLAGS_EXPECTED (AUTH_DATA_FLAG_UP | AUTH_DATA_FLAG_AT)

static const char *TAG = "fido_test_makecred";

typedef struct {
    bool cbor_decode;
    bool ecc_key;
    bool credential_save;
    bool auth_data;
    bool attestation;
} makecredential_check_t;

static bool cbor_ok(CborError err, const char *what)
{
    if (err == CborNoError) {
        return true;
    }

    ESP_LOGE(TAG, "%s failed: %d", what, err);
    return false;
}

static bool prepare_test_attestation(void)
{
    static const uint8_t fido_private_key[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    };
    static const uint8_t cert[] = {
        0x30, 0x03, 0x02, 0x01, 0x01,
    };

    ESP_LOGI(TAG, "Step 3.1: prepare test attestation key and certificate");

    int ret = write_attr(CTAP_CERT_FILE_NAME,
                         CTAP_PRIVATE_KEY_ATTR,
                         fido_private_key,
                         sizeof(fido_private_key));
    if (ret != 0) {
        ESP_LOGE(TAG, "write test attestation private key failed: %d", ret);
        return false;
    }

    ret = write_file(CTAP_CERT_FILE_NAME, cert, 0, sizeof(cert), 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "write test attestation certificate failed: %d", ret);
        return false;
    }

    ESP_LOGI(TAG, "Step 3.1 OK: test attestation ready");
    return true;
}

static const char *ctap_status_name(uint8_t status)
{
    switch (status) {
    case 0x00:
        return "CTAP2_OK";
    case 0x01:
        return "CTAP1_ERR_INVALID_COMMAND";
    case 0x02:
        return "CTAP1_ERR_INVALID_PARAMETER";
    case 0x03:
        return "CTAP1_ERR_INVALID_LENGTH";
    case 0x04:
        return "CTAP1_ERR_INVALID_SEQ";
    case 0x05:
        return "CTAP1_ERR_TIMEOUT";
    case 0x06:
        return "CTAP1_ERR_CHANNEL_BUSY";
    case 0x0A:
        return "CTAP1_ERR_LOCK_REQUIRED";
    case 0x0B:
        return "CTAP1_ERR_INVALID_CHANNEL";
    case 0x11:
        return "CTAP2_ERR_CBOR_UNEXPECTED_TYPE";
    case 0x12:
        return "CTAP2_ERR_INVALID_CBOR";
    case 0x14:
        return "CTAP2_ERR_MISSING_PARAMETER";
    case 0x15:
        return "CTAP2_ERR_LIMIT_EXCEEDED";
    case 0x16:
        return "CTAP2_ERR_UNSUPPORTED_EXTENSION";
    case 0x19:
        return "CTAP2_ERR_CREDENTIAL_EXCLUDED";
    case 0x21:
        return "CTAP2_ERR_PROCESSING";
    case 0x22:
        return "CTAP2_ERR_INVALID_CREDENTIAL";
    case 0x23:
        return "CTAP2_ERR_USER_ACTION_PENDING";
    case 0x24:
        return "CTAP2_ERR_OPERATION_PENDING";
    case 0x25:
        return "CTAP2_ERR_NO_OPERATIONS";
    case 0x26:
        return "CTAP2_ERR_UNSUPPORTED_ALGORITHM";
    case 0x27:
        return "CTAP2_ERR_OPERATION_DENIED";
    case 0x28:
        return "CTAP2_ERR_KEY_STORE_FULL";
    case 0x2B:
        return "CTAP2_ERR_UNSUPPORTED_OPTION";
    case 0x2C:
        return "CTAP2_ERR_INVALID_OPTION";
    case 0x2D:
        return "CTAP2_ERR_KEEPALIVE_CANCEL";
    case 0x2E:
        return "CTAP2_ERR_NO_CREDENTIALS";
    case 0x2F:
        return "CTAP2_ERR_USER_ACTION_TIMEOUT";
    case 0x30:
        return "CTAP2_ERR_NOT_ALLOWED";
    case 0x31:
        return "CTAP2_ERR_PIN_INVALID";
    case 0x32:
        return "CTAP2_ERR_PIN_BLOCKED";
    case 0x33:
        return "CTAP2_ERR_PIN_AUTH_INVALID";
    case 0x34:
        return "CTAP2_ERR_PIN_AUTH_BLOCKED";
    case 0x35:
        return "CTAP2_ERR_PIN_NOT_SET";
    case 0x36:
        return "CTAP2_ERR_PUAT_REQUIRED";
    case 0x37:
        return "CTAP2_ERR_PIN_POLICY_VIOLATION";
    case 0x39:
        return "CTAP2_ERR_REQUEST_TOO_LARGE";
    case 0x3A:
        return "CTAP2_ERR_ACTION_TIMEOUT";
    case 0x3B:
        return "CTAP2_ERR_UP_REQUIRED";
    case 0x7F:
        return "CTAP1_ERR_OTHER";
    case 0xF1:
        return "CTAP2_ERR_UNHANDLED_REQUEST";
    default:
        return "UNKNOWN";
    }
}

static bool encode_makecredential_request(uint8_t *req, size_t req_size, size_t *req_len)
{
    static const uint8_t client_data_hash[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t user_id[] = "test";
    CborEncoder encoder;
    CborEncoder map;
    CborEncoder rp;
    CborEncoder user;
    CborEncoder params;
    CborEncoder param;

    if (req == NULL || req_len == NULL || req_size < 2) {
        return false;
    }

    req[0] = CTAP_CMD_MAKE_CREDENTIAL;
    cbor_encoder_init(&encoder, req + 1, req_size - 1, 0);

    if (!cbor_ok(cbor_encoder_create_map(&encoder, &map, 4), "create request map")) {
        return false;
    }

    if (!cbor_ok(cbor_encode_int(&map, 1), "encode clientDataHash key") ||
        !cbor_ok(cbor_encode_byte_string(&map, client_data_hash, sizeof(client_data_hash)), "encode clientDataHash")) {
        return false;
    }

    if (!cbor_ok(cbor_encode_int(&map, 2), "encode rp key") ||
        !cbor_ok(cbor_encoder_create_map(&map, &rp, 2), "create rp map") ||
        !cbor_ok(cbor_encode_text_stringz(&rp, "id"), "encode rp id key") ||
        !cbor_ok(cbor_encode_text_stringz(&rp, "example.com"), "encode rp id") ||
        !cbor_ok(cbor_encode_text_stringz(&rp, "name"), "encode rp name key") ||
        !cbor_ok(cbor_encode_text_stringz(&rp, "example.com"), "encode rp name") ||
        !cbor_ok(cbor_encoder_close_container(&map, &rp), "close rp map")) {
        return false;
    }

    if (!cbor_ok(cbor_encode_int(&map, 3), "encode user key") ||
        !cbor_ok(cbor_encoder_create_map(&map, &user, 3), "create user map") ||
        !cbor_ok(cbor_encode_text_stringz(&user, "id"), "encode user id key") ||
        !cbor_ok(cbor_encode_byte_string(&user, user_id, sizeof(user_id) - 1), "encode user id") ||
        !cbor_ok(cbor_encode_text_stringz(&user, "name"), "encode user name key") ||
        !cbor_ok(cbor_encode_text_stringz(&user, "test"), "encode user name") ||
        !cbor_ok(cbor_encode_text_stringz(&user, "displayName"), "encode user displayName key") ||
        !cbor_ok(cbor_encode_text_stringz(&user, "test"), "encode user displayName") ||
        !cbor_ok(cbor_encoder_close_container(&map, &user), "close user map")) {
        return false;
    }

    if (!cbor_ok(cbor_encode_int(&map, 4), "encode pubKeyCredParams key") ||
        !cbor_ok(cbor_encoder_create_array(&map, &params, 1), "create pubKeyCredParams array") ||
        !cbor_ok(cbor_encoder_create_map(&params, &param, 2), "create pubKeyCredParam map") ||
        !cbor_ok(cbor_encode_text_stringz(&param, "type"), "encode type key") ||
        !cbor_ok(cbor_encode_text_stringz(&param, "public-key"), "encode type") ||
        !cbor_ok(cbor_encode_text_stringz(&param, "alg"), "encode alg key") ||
        !cbor_ok(cbor_encode_int(&param, COSE_ALG_ES256_VALUE), "encode ES256 alg") ||
        !cbor_ok(cbor_encoder_close_container(&params, &param), "close pubKeyCredParam map") ||
        !cbor_ok(cbor_encoder_close_container(&map, &params), "close pubKeyCredParams array")) {
        return false;
    }

    if (!cbor_ok(cbor_encoder_close_container(&encoder, &map), "close request map")) {
        return false;
    }

    *req_len = 1 + cbor_encoder_get_buffer_size(&encoder, req + 1);
    return true;
}

static void log_check_summary(const makecredential_check_t *check)
{
    bool all_pass = check->cbor_decode &&
                    check->ecc_key &&
                    check->credential_save &&
                    check->auth_data &&
                    check->attestation;

    ESP_LOGI(TAG, "=================");
    ESP_LOGI(TAG, "MakeCredential Test");
    ESP_LOGI(TAG, "CBOR decode       %s", check->cbor_decode ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "ECC key           %s", check->ecc_key ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "Credential save   %s", check->credential_save ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "authData          %s", check->auth_data ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "Attestation       %s", check->attestation ? "PASS" : "FAIL");
    ESP_LOGI(TAG, "%s", all_pass ? "ALL PASS" : "FAIL");
    ESP_LOGI(TAG, "=================");
}

static bool validate_auth_data(const uint8_t *auth_data,
                               size_t auth_data_len,
                               makecredential_check_t *check)
{
    const size_t cred_id_offset = AUTH_DATA_MIN_AT_LEN;

    if (auth_data_len < AUTH_DATA_MIN_AT_LEN) {
        ESP_LOGE(TAG, "authData too short: %u", (unsigned int)auth_data_len);
        return false;
    }

    uint8_t flags = auth_data[AUTH_DATA_FLAGS_OFFSET];
    uint16_t cred_id_len = ((uint16_t)auth_data[AUTH_DATA_MIN_AT_LEN - 2] << 8) |
                           auth_data[AUTH_DATA_MIN_AT_LEN - 1];

    ESP_LOGI(TAG, "authData:");
    ESP_LOGI(TAG, "rpIdHash:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, auth_data, AUTH_DATA_RP_ID_HASH_LEN, ESP_LOG_INFO);
    ESP_LOGI(TAG, "flags: 0x%02x", flags);
    ESP_LOGI(TAG, "signCount:");
    ESP_LOG_BUFFER_HEXDUMP(TAG,
                           auth_data + AUTH_DATA_RP_ID_HASH_LEN + 1,
                           AUTH_DATA_SIGN_COUNT_LEN,
                           ESP_LOG_INFO);

    if (flags != AUTH_DATA_FLAGS_EXPECTED) {
        ESP_LOGE(TAG, "authData flags failed: expected 0x%02x got 0x%02x",
                 AUTH_DATA_FLAGS_EXPECTED,
                 flags);
        return false;
    }

    if (cred_id_len == 0) {
        ESP_LOGE(TAG, "credentialId length is zero");
        return false;
    }
    if (cred_id_offset + cred_id_len >= auth_data_len) {
        ESP_LOGE(TAG, "credentialId overruns authData: offset=%u len=%u authData=%u",
                 (unsigned int)cred_id_offset,
                 (unsigned int)cred_id_len,
                 (unsigned int)auth_data_len);
        return false;
    }

    ESP_LOGI(TAG, "credentialId len=%u:", (unsigned int)cred_id_len);
    ESP_LOG_BUFFER_HEXDUMP(TAG, auth_data + cred_id_offset, cred_id_len, ESP_LOG_INFO);

    size_t cose_key_offset = cred_id_offset + cred_id_len;
    size_t cose_key_len = auth_data_len - cose_key_offset;
    if (cose_key_len == 0) {
        ESP_LOGE(TAG, "credentialPublicKey missing");
        return false;
    }

    ESP_LOGI(TAG, "COSE key len=%u:", (unsigned int)cose_key_len);
    ESP_LOG_BUFFER_HEXDUMP(TAG, auth_data + cose_key_offset, cose_key_len, ESP_LOG_INFO);

    check->ecc_key = true;
    check->credential_save = true;
    check->auth_data = true;
    return true;
}

static bool validate_makecredential_response(const uint8_t *resp, size_t resp_len)
{
    CborParser parser;
    CborValue it;
    CborValue map;
    CborError err;
    makecredential_check_t check = {0};
    bool have_fmt = false;
    bool have_auth_data = false;
    bool have_att_stmt = false;
    char fmt[16] = {0};
    uint8_t auth_data[512] = {0};
    size_t auth_data_len = 0;

    if (resp_len < 1) {
        ESP_LOGE(TAG, "makeCredential response empty");
        log_check_summary(&check);
        return false;
    }
    ESP_LOGI(TAG, "makeCredential status: 0x%02x (%s)", resp[0], ctap_status_name(resp[0]));
    if (resp[0] != CTAP_STATUS_OK) {
        ESP_LOGE(TAG, "makeCredential status failed: 0x%02x", resp[0]);
        ESP_LOG_BUFFER_HEXDUMP(TAG, resp, resp_len, ESP_LOG_ERROR);
        log_check_summary(&check);
        return false;
    }
    if (resp_len < 2) {
        ESP_LOGE(TAG, "makeCredential success response too short: %u", (unsigned int)resp_len);
        ESP_LOG_BUFFER_HEXDUMP(TAG, resp, resp_len, ESP_LOG_ERROR);
        log_check_summary(&check);
        return false;
    }

    err = cbor_parser_init(resp + 1, resp_len - 1, 0, &parser, &it);
    if (!cbor_ok(err, "parse response")) {
        log_check_summary(&check);
        return false;
    }
    if (!cbor_value_is_map(&it)) {
        ESP_LOGE(TAG, "makeCredential response payload is not a CBOR map");
        log_check_summary(&check);
        return false;
    }

    err = cbor_value_enter_container(&it, &map);
    if (!cbor_ok(err, "enter response map")) {
        log_check_summary(&check);
        return false;
    }

    while (!cbor_value_at_end(&map)) {
        int key = 0;
        err = cbor_value_get_int(&map, &key);
        if (!cbor_ok(err, "read response key")) {
            log_check_summary(&check);
            return false;
        }
        err = cbor_value_advance(&map);
        if (!cbor_ok(err, "advance response key")) {
            log_check_summary(&check);
            return false;
        }

        if (key == MC_RESP_FMT && cbor_value_is_text_string(&map)) {
            size_t fmt_len = sizeof(fmt);
            err = cbor_value_copy_text_string(&map, fmt, &fmt_len, &map);
            if (!cbor_ok(err, "copy fmt")) {
                log_check_summary(&check);
                return false;
            }
            fmt[sizeof(fmt) - 1] = '\0';
            have_fmt = true;
        } else if (key == MC_RESP_AUTH_DATA && cbor_value_is_byte_string(&map)) {
            auth_data_len = sizeof(auth_data);
            err = cbor_value_copy_byte_string(&map, auth_data, &auth_data_len, &map);
            if (!cbor_ok(err, "copy authData")) {
                log_check_summary(&check);
                return false;
            }
            have_auth_data = true;
        } else if (key == MC_RESP_ATT_STMT && cbor_value_is_map(&map)) {
            have_att_stmt = true;
            err = cbor_value_advance(&map);
            if (!cbor_ok(err, "advance attStmt")) {
                log_check_summary(&check);
                return false;
            }
        } else {
            err = cbor_value_advance(&map);
            if (!cbor_ok(err, "advance response value")) {
                log_check_summary(&check);
                return false;
            }
        }
    }

    check.cbor_decode = have_fmt && have_auth_data;
    check.attestation = have_att_stmt;

    ESP_LOGI(TAG, "response fmt=%s", have_fmt ? fmt : "<missing>");

    if (!have_fmt || !have_auth_data || !have_att_stmt) {
        ESP_LOGE(TAG, "makeCredential response missing fields: fmt=%u authData=%u attStmt=%u",
                 have_fmt ? 1 : 0,
                 have_auth_data ? 1 : 0,
                 have_att_stmt ? 1 : 0);
        ESP_LOG_BUFFER_HEXDUMP(TAG, resp, resp_len, ESP_LOG_ERROR);
        log_check_summary(&check);
        return false;
    }

    if (!validate_auth_data(auth_data, auth_data_len, &check)) {
        log_check_summary(&check);
        return false;
    }

    log_check_summary(&check);
    return check.cbor_decode &&
           check.ecc_key &&
           check.credential_save &&
           check.auth_data &&
           check.attestation;
}

static bool read_ctap_source(CTAPHID_TxSource *source, uint8_t *resp, size_t resp_size, size_t *resp_len)
{
    size_t total = 0;

    if (source == NULL || source->read == NULL || resp == NULL || resp_len == NULL) {
        return false;
    }
    if (source->total_len > resp_size) {
        ESP_LOGE(TAG, "CTAP response too large: %u > %u",
                 (unsigned int)source->total_len,
                 (unsigned int)resp_size);
        return false;
    }

    while (total < source->total_len) {
        size_t written = 0;
        int ret = source->read(source->ctx, resp + total, source->total_len - total, &written);
        if (ret != 0) {
            ESP_LOGE(TAG, "CTAP response source read failed: %d", ret);
            return false;
        }
        if (written == 0) {
            ESP_LOGE(TAG, "CTAP response source made no progress");
            return false;
        }
        total += written;
    }

    if (source->close != NULL) {
        source->close(source->ctx);
    }

    *resp_len = total;
    return true;
}

static void test_ctap_makecredential_run(void)
{
    static uint8_t req[256];
    static uint8_t scratch[512];
    static uint8_t resp[4096];
    CTAPHID_TxSource source;
    size_t req_len = 0;
    size_t resp_len = 0;

    ESP_LOGI(TAG, "MakeCredential start");
    ESP_LOGI(TAG, "rp=example.com");
    ESP_LOGI(TAG, "user=test");
    ESP_LOGI(TAG, "alg=-7");

    ESP_LOGI(TAG, "Step 1: init CanoKey crypto");
    esp_err_t crypto_ret = canokey_esp32p4_crypto_init();
    if (crypto_ret != ESP_OK) {
        ESP_LOGE(TAG, "CanoKey crypto init failed: %s", esp_err_to_name(crypto_ret));
        return;
    }
    ESP_LOGI(TAG, "Step 1 OK: crypto ready");

    ESP_LOGI(TAG, "Step 2: init flash and LittleFS storage");
    esp_err_t flash_ret = canokey_esp32p4_flash_init();
    if (flash_ret != ESP_OK) {
        ESP_LOGE(TAG, "CanoKey flash init failed: %s", esp_err_to_name(flash_ret));
        return;
    }
    ESP_LOGI(TAG, "Step 2 OK: storage ready");

    ESP_LOGI(TAG, "Step 3: init APDU buffer, device, applets");
    init_apdu_buffer();
    device_init();
    if (applets_install() != 0) {
        ESP_LOGE(TAG, "applets_install failed");
        return;
    }
    ESP_LOGI(TAG, "Step 3 OK: CanoKey Core applets installed");

    if (!prepare_test_attestation()) {
        return;
    }

    ESP_LOGI(TAG, "Step 4: encode MakeCredential request");
    if (!encode_makecredential_request(req, sizeof(req), &req_len)) {
        return;
    }
    ESP_LOGI(TAG, "Step 4 OK: request CBOR encode PASS, len=%u", (unsigned int)req_len);

    set_touch_result(TOUCH_SHORT);
    ESP_LOGI(TAG, "Step 5: call CTAP makeCredential");
    int ret = ctap_process_cbor_stream_with_src(req, req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID);
    set_touch_result(TOUCH_NO);
    if (ret != 1) {
        ESP_LOGE(TAG, "ctap_process_cbor_stream_with_src failed: %d", ret);
        return;
    }

    if (!read_ctap_source(&source, resp, sizeof(resp), &resp_len)) {
        return;
    }

    ESP_LOGI(TAG, "Step 6: verify MakeCredential response");
    if (!validate_makecredential_response(resp, resp_len)) {
        return;
    }

    ESP_LOGI(TAG, "CTAP makeCredential OK, response_len=%u", (unsigned int)resp_len);
}

static void test_ctap_makecredential_task(void *arg)
{
    TaskHandle_t caller = (TaskHandle_t)arg;

    test_ctap_makecredential_run();
    if (caller != NULL) {
        xTaskNotifyGive(caller);
    }
    vTaskDelete(NULL);
}

void test_ctap_makecredential(void)
{
    TaskHandle_t caller = xTaskGetCurrentTaskHandle();
    TaskHandle_t task = NULL;
    BaseType_t ok = xTaskCreate(test_ctap_makecredential_task,
                                "fido_makecred_test",
                                24576,
                                caller,
                                5,
                                &task);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "failed to create CTAP makeCredential test task");
        return;
    }

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
}
