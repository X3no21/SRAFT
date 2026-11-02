/* =============================
 * File: attestation_test_region.c
 * Description: Constant data in flash used by the failed-attestation scenarios of the experiments.
 * ============================= */

#include "attestation_test_region.h"
#include <stdlib.h>
#include <string.h>
#include "esp_flash.h"
#include "esp_log.h"
#include "esp_random.h"
#include "spi_flash_mmap.h"

static const char *TAG = "TEST_REGION";

/* The region is part of the firmware image and is attested like the rest of it, but the firmware never
 * uses its content. The tampered test images are obtained from the reference image by overwriting part
 * of it with random bytes (scripts/tests/make_tampered_image.py), so that the device keeps working while
 * its image differs from the reference. The region fills a sector of the flash, so that it can also be
 * rewritten while the device runs (attestation_test_region_tamper). */
const uint8_t sraft_attested_test_region[ATTESTATION_TEST_REGION_SIZE] __attribute__((aligned(ATTESTATION_TEST_REGION_SIZE))) = {
    [0 ... ATTESTATION_TEST_REGION_SIZE - 1] = ATTESTATION_TEST_REGION_BYTE
};

bool attestation_test_region_tamper(size_t bytes) {
    if (bytes == 0 || bytes > ATTESTATION_TEST_REGION_SIZE) return false;
    size_t address = spi_flash_cache2phys(sraft_attested_test_region);
    if (address == SPI_FLASH_CACHE2PHYS_FAIL || address % ATTESTATION_TEST_REGION_SIZE != 0) {
        ESP_LOGE(TAG, "The test region is not mapped to a sector of the flash.");
        return false;
    }
    uint8_t *sector = malloc(ATTESTATION_TEST_REGION_SIZE);
    if (!sector) return false;
    memcpy(sector, sraft_attested_test_region, ATTESTATION_TEST_REGION_SIZE);
    esp_fill_random(sector, bytes);
    esp_err_t err = esp_flash_erase_region(NULL, address, ATTESTATION_TEST_REGION_SIZE);
    if (err == ESP_OK) err = esp_flash_write(NULL, sector, address, ATTESTATION_TEST_REGION_SIZE);
    free(sector);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Rewriting the test region failed: %s", esp_err_to_name(err));
        return false;
    }
    ESP_LOGW(TAG, "Test region rewritten at runtime: %u bytes at flash address 0x%x now differ from the reference.", (unsigned)bytes, (unsigned)address);
    return true;
}
