idf_component_register(
    SRCS
        "test_sha256.c"
        "test_hmac_sha256.c"
        "test_aes.c"
        "test_random.c"
        "test_ecc.c"
        "test_public_key_verify.c"
        "test_ecdsa_sign.c"
        "test_ecdsa_verify.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        canokey-port
        log
        mbedtls
)
