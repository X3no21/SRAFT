/* =============================
 * File: puf_extractor.c
 * Description: Fuzzy extractor over the retained cells of the SRAM PUF and layout of the
 * responses over disjoint groups of cells.
 * ============================= */

#include "puf_extractor.h"
#include <string.h>

/**
 * @brief Collects the positions of the next BCH_N retained cells, advancing the cursor.
 */
static void next_block_positions(const uint32_t *mask, int size_words, int *cursor, int positions[BCH_N]) {
    int found = 0;

    while (found < BCH_N && *cursor < size_words * 32) {
        int word = *cursor / 32;
        int bit = *cursor % 32;

        if ((mask[word] >> bit) & 1u) {
            positions[found++] = *cursor;
        }

        (*cursor)++;
    }
}

static void read_packed_block(const uint8_t *packed, int block_index, int block[BCH_N]) {
    for (int i = 0; i < BCH_N; i++) {
        int bit_index = block_index * BCH_N + i;
        block[i] = (packed[bit_index / 8] >> (bit_index % 8)) & 1u;
    }
}

static void write_packed_block(uint8_t *packed, int block_index, const int block[BCH_N]) {
    for (int i = 0; i < BCH_N; i++) {
        int bit_index = block_index * BCH_N + i;

        if (block[i]) {
            packed[bit_index / 8] |= (uint8_t)(1u << (bit_index % 8));
        } else {
            packed[bit_index / 8] &= (uint8_t)~(1u << (bit_index % 8));
        }
    }
}

int puf_extractor_count_blocks(const uint32_t *mask, int size_words) {
    int retained = 0;

    for (int i = 0; i < size_words; i++) {
        retained += __builtin_popcount(mask[i]);
    }

    return retained / BCH_N;
}

void puf_extractor_generate(const uint32_t *reading, const uint32_t *mask, int size_words, int total_blocks,
                            uint8_t *helper, uint32_t (*random_word)(void)) {
    int cursor = 0;

    for (int b = 0; b < total_blocks; b++) {
        int positions[BCH_N];
        int message[BCH_FINGERPRINT_K];
        int codeword[BCH_N];

        next_block_positions(mask, size_words, &cursor, positions);

        uint32_t random_bits = random_word();
        for (int i = 0; i < BCH_FINGERPRINT_K; i++) {
            message[i] = (int)((random_bits >> i) & 1u);
        }

        bch_encode(&bch_code_fingerprint, message, codeword);

        for (int i = 0; i < BCH_N; i++) {
            codeword[i] ^= (int)((reading[positions[i] / 32] >> (positions[i] % 32)) & 1u);
        }

        write_packed_block(helper, b, codeword);
    }
}

int puf_extractor_reproduce(const uint32_t *reading, const uint32_t *mask, int size_words, int total_blocks,
                            const uint8_t *helper, uint8_t *cells, uint8_t *failed_blocks) {
    int cursor = 0;
    int failures = 0;

    memset(failed_blocks, 0, (total_blocks + 7) / 8);

    for (int b = 0; b < total_blocks; b++) {
        int positions[BCH_N];
        int helper_block[BCH_N];
        int noisy_codeword[BCH_N];

        next_block_positions(mask, size_words, &cursor, positions);
        read_packed_block(helper, b, helper_block);

        for (int i = 0; i < BCH_N; i++) {
            int noisy_bit = (int)((reading[positions[i] / 32] >> (positions[i] % 32)) & 1u);
            noisy_codeword[i] = helper_block[i] ^ noisy_bit;
        }

        if (bch_decode(&bch_code_fingerprint, noisy_codeword) < 0) {
            failed_blocks[b / 8] |= (uint8_t)(1u << (b % 8));
            failures++;
        }

        for (int i = 0; i < BCH_N; i++) {
            noisy_codeword[i] ^= helper_block[i];
        }

        write_packed_block(cells, b, noisy_codeword);
    }

    return failures;
}

bool puf_extractor_response_cells(const uint8_t *cells, const uint8_t *failed_blocks, int total_blocks,
                                  int response_index, uint8_t *out) {
    if (response_index < 0 || (response_index + 1) * PUF_BLOCKS_PER_RESPONSE > total_blocks) {
        return false;
    }

    int first_block = response_index * PUF_BLOCKS_PER_RESPONSE;
    memset(out, 0, PUF_RESPONSE_CELL_BYTES);

    for (int b = 0; b < PUF_BLOCKS_PER_RESPONSE; b++) {
        int block[BCH_N];

        if ((failed_blocks[(first_block + b) / 8] >> ((first_block + b) % 8)) & 1u) {
            return false;
        }

        read_packed_block(cells, first_block + b, block);
        write_packed_block(out, b, block);
    }

    return true;
}
