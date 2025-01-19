// Auth: smurfd, 2023 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#ifndef HASH_H
#define HASH_H 1
#include <stdint.h>
#define DIV8(x) x >> 3
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m // Imitate pythons %. -1 % 5 = 4, not -1
#define SHA3_BITS 1024 // SHA3-256 = 512, SHA3-512 = 1024 (default)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
void hash_new(char *s, const uint8_t *n);
void hash_shake_new(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen);
// precalculated RC
static const uint8_t rc_precalc[24][7] = {
  {1, 0, 0, 0, 0, 0, 0},
  {0, 1, 0, 1, 1, 0, 0},
  {0, 1, 1, 1, 1, 0, 1},
  {0, 0, 0, 0, 1, 1, 1},
  {1, 1, 1, 1, 1, 0, 0},
  {1, 0, 0, 0, 0, 1, 0},
  {1, 0, 0, 1, 1, 1, 1},
  {1, 0, 1, 0, 1, 0, 1},
  {0, 1, 1, 1, 0, 0, 0},
  {0, 0, 1, 1, 0, 0, 0},
  {1, 0, 1, 0, 1, 1, 0},
  {0, 1, 1, 0, 0, 1, 0},
  {1, 1, 1, 1, 1, 1, 0},
  {1, 1, 1, 1, 0, 0, 1},
  {1, 0, 1, 1, 1, 0, 1},
  {1, 1, 0, 0, 1, 0, 1},
  {0, 1, 0, 0, 1, 0, 1},
  {0, 0, 0, 1, 0, 0, 1},
  {0, 1, 1, 0, 1, 0, 0},
  {0, 1, 1, 0, 0, 1, 1},
  {1, 0, 0, 1, 1, 1, 1},
  {0, 0, 0, 1, 1, 0, 1},
  {1, 0, 0, 0, 0, 1, 0},
  {0, 0, 1, 0, 1, 1, 1}
};
#endif
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
