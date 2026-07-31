file(GLOB_RECURSE COMPONENT_SRCS 
    "*.c"
)

idf_component_register(
    SRCS ${COMPONENT_SRCS}

    INCLUDE_DIRS
        "."
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

    EMBED_TXTFILES
        "certs/ca.crt"
        "certs/device.crt"
        "certs/device.key"
)