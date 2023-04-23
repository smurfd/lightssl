#ifndef FIPS202_H
#define FIPS202_H
#include <stddef.h>
#include <stdint.h>
#include "lightdefs.h"

#define SHAKE256_RATE 136

typedef struct {u64 s[25];} keccak_state;

void KeccakF1600_StatePermute(u64 state[25]);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#endif
