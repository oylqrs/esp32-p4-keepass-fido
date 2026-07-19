idf_component_register(
    SRCS
        "test_ctap_makecredential.c"
        "credential_test.c"
        "test_fido_storage_loop.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        canokey-port
        log
        mbedtls
)
