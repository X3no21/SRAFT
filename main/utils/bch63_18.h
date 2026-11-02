#ifndef BCH63_18_H
#define BCH63_18_H

// standard libraries
#include <stdbool.h>

// constants
// The file name is historical: this module now provides several BCH codes over the same GF(2^6),
// selected per call site through the bch_code_type descriptors below, rather than the single
// BCH(63,18) it originally implemented.
#define BCH_N 63 // codeword length (2^6 - 1, defined over GF(2^6)), shared by every code below
#define BCH_MAX_T 15 // largest correction capability across the codes below, used to size the decoder's scratch arrays
#define BCH_MAX_PARITY (BCH_N - 7) // largest parity length across the codes below, used to size the encoder's shift register

// message length and correction capability of the channel-bootstrap code, BCH(63,7,15): chosen so
// Rep() keeps correcting through the PUF aging range used in the paper's experiments (5% nominal
// BER + 2%/cycle over up to 10 cycles); see fuzzy_extractor.h
#define BCH_K 7
#define BCH_T 15

// message length and correction capability of the fingerprint code, BCH(63,18,10): the SRAM
// fingerprint is read by one party at provisioning and again at each boot, with a measured 0.60%
// error rate between readings once the stability filter has run, so t=10 (15.9% of the block)
// already leaves a wide margin while leaking 45 helper-data bits per block instead of the 56 a
// t=15 code would leak, which is what keeps the min-entropy budget of the derived key positive
#define BCH_FINGERPRINT_K 18
#define BCH_FINGERPRINT_T 10

// descriptor of one BCH code over GF(2^6): every code here shares BCH_N and the field tables, and
// differs only in message length, correction capability, and generator polynomial
typedef struct {
    int k; // message length
    int t; // maximum number of correctable errors per block
    const int *generator_poly; // coefficients in ascending degree order (0 .. n-k-1); the monic highest-degree term is implicit
} bch_code_type;

// the two codes this project uses
extern const bch_code_type bch_code_channel; // BCH(63,7,15), channel bootstrap (fuzzy_extractor.c)
extern const bch_code_type bch_code_fingerprint; // BCH(63,18,10), SRAM fingerprint (puf.c)

// functions for BCH encoding/decoding over GF(2^6), used by the fuzzy extractors
void bch_init(void); // initializes the GF(2^6) tables (must be called once before encoding/decoding)
void bch_encode(const bch_code_type *code, const int *msg, int codeword[BCH_N]); // systematic encoding: msg at indices 0..k-1 (high degrees), parity at indices k..62 (low degrees)
int bch_decode(const bch_code_type *code, int received[BCH_N]); // in-place decoding; returns the number of corrected errors, or -1 if the number of errors exceeds the code's t

#endif
