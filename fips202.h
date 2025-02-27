#ifndef FIPS_202_H
#define FIPS_202_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Incremental SHA-3/SHAKE context */
typedef struct {
    uint64_t state[25];  /* Keccak state */
    size_t absorbed;     /* Bytes absorbed */
    int done;            /* Finalization flag */
} shake256incctx;

/* SHAKE256 Incremental Interface */

/**
 * Initialize a SHAKE256 incremental hashing context
 * @param ctx Pointer to the context to initialize
 */
void shake256_inc_init(shake256incctx *ctx);

/**
 * Absorb input data into the SHAKE256 context
 * @param ctx Pointer to the context
 * @param input Input data
 * @param inlen Length of input data
 */
void shake256_inc_absorb(shake256incctx *ctx, const uint8_t *input, size_t inlen);

/**
 * Finalize the SHAKE256 absorption phase
 * @param ctx Pointer to the context
 */
void shake256_inc_finalize(shake256incctx *ctx);

/**
 * Squeeze output from the SHAKE256 context
 * @param output Buffer to receive output
 * @param outlen Length of output to generate
 * @param ctx Pointer to the context
 */
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *ctx);

/**
 * Release and clean up the SHAKE256 context
 * @param ctx Pointer to the context
 */
void shake256_inc_ctx_release(shake256incctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* FIPS_202_H */