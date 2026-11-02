file(GLOB_RECURSE COMPONENT_SRCS 
    "*.c"
)

# The tracked files in certs/ are placeholders. Real certificates are kept in certs_local/
# (gitignored) and used when present.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs_local/device.key")
    set(SRAFT_CERT_DIR "certs_local")
else()
    set(SRAFT_CERT_DIR "certs")
    message(WARNING "main/certs_local/ not found: embedding the placeholder certificates, the TLS and MQTTS baselines will fail.")
endif()

idf_component_register(
    SRCS ${COMPONENT_SRCS}

    INCLUDE_DIRS
        "."
        "attack"
        "auth"
        "rest_api"
        "esp32_config"
        "device_integrity_verification"
        "raft"
        "utils"

    REQUIRES
        mbedtls
        esp_wifi
        nvs_flash
        esp_https_server
        esp-tls
        app_update
        bootloader_support
        esp_partition
        spi_flash

    EMBED_TXTFILES
        "${SRAFT_CERT_DIR}/ca.crt"
        "${SRAFT_CERT_DIR}/device.crt"
        "${SRAFT_CERT_DIR}/device.key"
)

# Test-only adversary hooks (attack-resilience campaign). Off by default: the ordinary firmware is
# built without them. Enable with: idf.py -D SRAFT_ATTACK_HOOKS=ON ...
if(SRAFT_ATTACK_HOOKS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SRAFT_ATTACK_HOOKS=1)
    message(STATUS "SRAFT_ATTACK_HOOKS enabled: this image contains the test-only adversary hooks.")
endif()

