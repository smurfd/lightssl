//                                                                            //
#ifndef LIGHTDEFS_H
#define LIGHTDEFS_H 1
#include <stdint.h>

// Only defines here, no typedefs
#define cc const char
#define u128 unsigned __int128
#define cuc const uint8_t
#define u64 unsigned long long int // because linux u64 is not same as on mac
// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m

// SSL
#define RD() (rand() & 0x7FFFFFFFFFFFFFFF)
#define RAND64() RD() << 48 ^ RD() << 35 ^ RD() << 22 ^ RD() << 9 ^ RD() >> 4

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
#define BT 8
#define KB 48
#define KB2 KB * 2
#define DI (KB / BT)
#define DI2 (DI * 2)
#define EVEN(p) (!(p[0] & 1))

typedef struct pt {u64 x[DI], y[DI];} pt;
typedef struct prng_t {u64 a, b, c, d;} prng_t;

static u64 curve_p[DI] = {0x00000000ffffffff, 0xffffffff00000000,
  0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff,0xffffffffffffffff},
  curve_b[DI] = {0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4},
  curve_n[DI] = {0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static pt curve_g = {{0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38,
  0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537}, {
  0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
  0x5d9e98bf9292dc29, 0x3617de4a96262c6f}};
static prng_t prng_ctx;
#endif
