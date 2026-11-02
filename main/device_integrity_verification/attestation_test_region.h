/* =============================
 * File: attestation_test_region.h
 * Description: Constant data in flash used by the failed-attestation scenario of the experiments.
 * ============================= */

#ifndef ATTESTATION_TEST_REGION_H
#define ATTESTATION_TEST_REGION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define ATTESTATION_TEST_REGION_SIZE 4096
// Content of the region in the reference image; the test scripts look for it in the binary.
#define ATTESTATION_TEST_REGION_BYTE 0x5A

extern const uint8_t sraft_attested_test_region[ATTESTATION_TEST_REGION_SIZE];

/**
 * @brief Overwrites the first bytes of the test region in flash with random values while the device runs.
 * For tests only: it simulates a remote alteration of the software of a member. The image no longer
 * matches its digest, so the device does not boot again until it is flashed.
 * @param bytes Number of bytes overwritten, at most ATTESTATION_TEST_REGION_SIZE.
 * @return true if the flash was rewritten.
 */
bool attestation_test_region_tamper(size_t bytes);

#endif
