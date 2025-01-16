// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTDEFS_H
#define LIGHTDEFS_H 1
#include <stdint.h>

// Only defines here, no typedefs
#define u64 unsigned long long int // because linux uint64_t is not same as on mac

#define EVEN(p) (!(p[0] & 1))

// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m

// SSL
#define RAND64() (rand() & 0x7fffffffffffffff) << 48 ^ (rand() & 0x7fffffffffffffff) << 35 ^\
                 (rand() & 0x7fffffffffffffff) << 22 ^ (rand() & 0x7fffffffffffffff) << 9 ^\
                 (rand() & 0x7fffffffffffffff) >> 4

// Lightciphers
#define NB 4
#define NK 8
#define NR 14
#define NB4 NB * 4
#define NK4 NK * 4
#define NBR1 NB * (NR + 1)
#define BBL 4 * NB * sizeof(uint8_t)

// Lightcrypto
#define BLOCK 1024
#define LEN 4096

// Lighthash3
#define SHA3_BITS 1024 // SHA3-256 = 512, SHA3-512 = 1024 (default)

// Lightkeys
#define BYTES 48
#define DIGITS (BYTES / 8)

typedef struct pt {u64 x[DIGITS], y[DIGITS];} pt;
typedef struct prng_t {u64 a, b, c, d;} prng_t;
#endif
