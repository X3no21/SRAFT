/* =============================
 * File: puf_extractor.h
 * Description: Fuzzy extractor over the retained cells of the SRAM PUF and layout of the
 * responses over disjoint groups of cells. The module has no dependency on the platform.
 * ============================= */

#ifndef PUF_EXTRACTOR_H
#define PUF_EXTRACTOR_H

#include <stdbool.h>
#include <stdint.h>
#include "bch63_18.h"

// Each response is drawn from its own group of BCH blocks, never shared with another response.
// A block of 63 cells protected by BCH(63,18,10) keeps 18 bits that the public helper data does
// not disclose, so 8 blocks leave 144 bits behind a 128-bit response.
#define PUF_BLOCKS_PER_RESPONSE 8
#define PUF_RESPONSE_CELLS (PUF_BLOCKS_PER_RESPONSE * BCH_N)
#define PUF_RESPONSE_CELL_BYTES ((PUF_RESPONSE_CELLS + 7) / 8)

/**
 * @brief Counts the BCH blocks that the cells selected by a stability mask can fill.
 * @param mask The stability mask, one bit per cell (1 = retained).
 * @param size_words The size of the mask in 32-bit words.
 * @return The number of complete blocks of BCH_N retained cells.
 */
int puf_extractor_count_blocks(const uint32_t *mask, int size_words);

/**
 * @brief Gen step of the fuzzy extractor, run once at provisioning.
 * @details For every block of retained cells it draws a random BCH message, encodes it, and
 * stores the code offset (codeword XOR cells) as helper data. This is the code-offset secure
 * sketch: the helper data is public, and recovering the cells from it requires a reading of the
 * same silicon.
 * @param reading The reading of the cells taken at provisioning.
 * @param mask The stability mask.
 * @param size_words The size of reading and mask in 32-bit words.
 * @param total_blocks The number of blocks, as returned by puf_extractor_count_blocks.
 * @param helper Output buffer for the bit-packed helper data, (total_blocks * BCH_N + 7) / 8 bytes.
 * @param random_word Source of random 32-bit words.
 */
void puf_extractor_generate(const uint32_t *reading, const uint32_t *mask, int size_words, int total_blocks,
                            uint8_t *helper, uint32_t (*random_word)(void));

/**
 * @brief Rep step of the fuzzy extractor, run at every boot.
 * @details It corrects a noisy reading of every block back to the value read at provisioning and
 * writes the corrected retained cells, in order and bit-packed, to the output.
 * @param reading The reading of the cells taken at this boot.
 * @param mask The stability mask stored at provisioning.
 * @param size_words The size of reading and mask in 32-bit words.
 * @param total_blocks The number of blocks.
 * @param helper The helper data stored at provisioning.
 * @param cells Output buffer for the corrected cells, (total_blocks * BCH_N + 7) / 8 bytes.
 * @param failed_blocks Output bitmap, one bit per block, set when a block had more errors than the
 * code corrects; (total_blocks + 7) / 8 bytes.
 * @return The number of blocks that could not be corrected.
 */
int puf_extractor_reproduce(const uint32_t *reading, const uint32_t *mask, int size_words, int total_blocks,
                            const uint8_t *helper, uint8_t *cells, uint8_t *failed_blocks);

/**
 * @brief Copies the cells of one response out of the corrected cells.
 * @param cells The corrected cells produced by puf_extractor_reproduce.
 * @param failed_blocks The bitmap of the blocks that could not be corrected.
 * @param total_blocks The number of blocks.
 * @param response_index The index of the response, i.e., of its group of blocks.
 * @param out Output buffer of PUF_RESPONSE_CELL_BYTES bytes.
 * @return false if the index is out of range or one of the blocks could not be corrected.
 */
bool puf_extractor_response_cells(const uint8_t *cells, const uint8_t *failed_blocks, int total_blocks,
                                  int response_index, uint8_t *out);

#endif // PUF_EXTRACTOR_H
