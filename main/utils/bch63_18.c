// external libraries
#include "bch63_18.h"
#include <string.h>

// internal constants
#define GF_M 6            // GF(2^m), m=6 -> GF(64)
#define GF_PRIM_POLY 0x43 // primitive polynomial x^6 + x + 1 = 0b1000011

// tables of GF(2^6): alpha_to[i] = alpha^i, index_of[alpha^i] = i (log(0) = -1)
static int alpha_to[BCH_N + 1];
static int index_of[BCH_N + 1];

// coefficients of the generator polynomials, in ascending degree order; the highest-degree term
// is monic and implicit, so it is not stored. Both were verified against the Python `galois`
// library (galois.BCH(63,7) and galois.BCH(63,18) over GF(2^6)).
static const int generator_poly_channel[BCH_N - BCH_K] = {
    1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1,
    0, 0, 1, 0, 1, 0
};

static const int generator_poly_fingerprint[BCH_N - BCH_FINGERPRINT_K] = {
    1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1,
    0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0
};

const bch_code_type bch_code_channel = {BCH_K, BCH_T, generator_poly_channel};
const bch_code_type bch_code_fingerprint = {BCH_FINGERPRINT_K, BCH_FINGERPRINT_T, generator_poly_fingerprint};

// flag for whether the tables of GF(2^6) have already been built
static bool bch_tables_initialized = false;

// function to initialize the tables of GF(2^6) starting from the primitive polynomial
void bch_init(void) {
    int mask = 1;
    for (int i = 0; i < GF_M; i++) {
        alpha_to[i] = mask;
        index_of[mask] = i;
        mask <<= 1;
    }

    alpha_to[GF_M] = GF_PRIM_POLY & ((1 << GF_M) - 1);
    index_of[alpha_to[GF_M]] = GF_M;

    mask = 1 << (GF_M - 1);
    for (int i = GF_M + 1; i < BCH_N; i++) {
        if (alpha_to[i - 1] & mask) {
            alpha_to[i] = alpha_to[GF_M] ^ ((alpha_to[i - 1] ^ (alpha_to[i - 1] & mask)) << 1);
        } else {
            alpha_to[i] = alpha_to[i - 1] << 1;
        }
        index_of[alpha_to[i]] = i;
    }

    index_of[0] = -1;
    alpha_to[BCH_N] = 1;

    bch_tables_initialized = true;
}

// local function to initialize the tables of GF(2^6), if not already done
static void ensure_bch_init(void) {
    if (bch_tables_initialized == false) {
        bch_init();
    }
}

// function for systematic encoding: msg[0..k-1] (high degrees) -> codeword[0..62] (msg + parity)
void bch_encode(const bch_code_type *code, const int *msg, int codeword[BCH_N]) {
    ensure_bch_init();

    int parity_degree = BCH_N - code->k;
    int feedback_reg[BCH_MAX_PARITY];
    memset(feedback_reg, 0, sizeof(feedback_reg));

    for (int i = 0; i < code->k; i++) {
        int feedback = msg[i] ^ feedback_reg[parity_degree - 1];

        for (int j = parity_degree - 1; j > 0; j--) {
            feedback_reg[j] = feedback_reg[j - 1] ^ (feedback ? code->generator_poly[j] : 0);
        }

        feedback_reg[0] = feedback ? code->generator_poly[0] : 0;
    }

    for (int i = 0; i < code->k; i++) {
        codeword[i] = msg[i];
    }

    for (int i = 0; i < parity_degree; i++) {
        codeword[code->k + i] = feedback_reg[parity_degree - 1 - i];
    }
}

// function for decoding: corrects received[] in place, returns the number of corrected errors or -1 in case of failure
int bch_decode(const bch_code_type *code, int received[BCH_N]) {
    ensure_bch_init();

    const int t = code->t;

    int syndrome_log[2 * BCH_MAX_T + 1];
    bool all_zero = true;

    for (int i = 1; i <= 2 * t; i++) {
        int s = 0;

        for (int j = 0; j < BCH_N; j++) {
            if (received[j]) {
                int degree = BCH_N - 1 - j;
                s ^= alpha_to[(degree * i) % BCH_N];
            }
        }

        syndrome_log[i] = index_of[s];
        if (s != 0) all_zero = false;
    }

    if (all_zero) return 0;

    int sigma[2 * BCH_MAX_T + 2];
    int prev_sigma[2 * BCH_MAX_T + 2];
    memset(sigma, 0, sizeof(sigma));
    memset(prev_sigma, 0, sizeof(prev_sigma));
    sigma[0] = 1;
    prev_sigma[0] = 1;
    int locator_degree = 0;
    int shift = 1;
    int last_discrepancy = 1;

    for (int n = 0; n < 2 * t; n++) {
        int discrepancy = (syndrome_log[n + 1] == -1) ? 0 : alpha_to[syndrome_log[n + 1]];

        for (int i = 1; i <= locator_degree; i++) {
            if (sigma[i] && syndrome_log[n + 1 - i] != -1) {
                int a = index_of[sigma[i]];
                int b = syndrome_log[n + 1 - i];
                discrepancy ^= alpha_to[(a + b) % BCH_N];
            }
        }

        if (discrepancy == 0) {
            shift++;
        } else {
            int tmp_sigma[2 * BCH_MAX_T + 2];
            memcpy(tmp_sigma, sigma, sizeof(sigma));

            int discrepancy_log = index_of[discrepancy];
            int last_discrepancy_log = index_of[last_discrepancy];
            int coefficient_log = (discrepancy_log - last_discrepancy_log + BCH_N) % BCH_N;

            for (int i = 0; i <= 2 * t; i++) {
                int shifted_term = (i - shift >= 0) ? prev_sigma[i - shift] : 0;
                if (shifted_term) {
                    int shifted_log = index_of[shifted_term];
                    sigma[i] ^= alpha_to[(coefficient_log + shifted_log) % BCH_N];
                }
            }

            if (2 * locator_degree <= n) {
                locator_degree = n + 1 - locator_degree;
                memcpy(prev_sigma, tmp_sigma, sizeof(tmp_sigma));
                last_discrepancy = discrepancy;
                shift = 1;
            } else {
                shift++;
            }
        }
    }

    if (locator_degree > t) return -1;

    int error_positions[BCH_MAX_T];
    int num_errors = 0;

    for (int i = 0; i < BCH_N; i++) {
        int sum = sigma[0] ? 1 : 0;

        for (int j = 1; j <= locator_degree; j++) {
            if (sigma[j]) {
                int exp = (index_of[sigma[j]] + j * i) % BCH_N;
                sum ^= alpha_to[exp];
            }
        }

        if (sum == 0) {
            if (num_errors >= t) return -1;
            int degree = (BCH_N - i) % BCH_N;
            error_positions[num_errors++] = (BCH_N - 1) - degree;
        }
    }

    if (num_errors != locator_degree) return -1;

    for (int i = 0; i < num_errors; i++) {
        received[error_positions[i]] ^= 1;
    }

    return num_errors;
}
