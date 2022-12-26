//                                                                            //
#ifndef DEFS_H
#define DEFS_H 1
#include <stdint.h>

// Only defines here, no typedefs
#define i08 int8_t
#define u08 uint8_t
#define u32 uint32_t
#define cc const char
#define ui unsigned int
#define b08 unsigned char
#define cu8 const uint8_t
#define u128 unsigned __int128
#define cuc const unsigned char
#define u64 long long unsigned int

// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m

// SSL
#define RAND() (rand() & 0x7FFFFFFFFFFFFFFF)
#define RAND64() ((u64)(RAND()) << 48) ^ ((u64)(RAND()) << 35) ^ \
  ((u64)(RAND()) << 22) ^ ((u64)(RAND()) << 9) ^ ((u64)(RAND()) >> 4)

// TLS
#define TLSCIPHER 222
#define TLSVERSION 0x304
#define TLSCIPHERAVAIL 222
#define TLSCOMPRESSION 123

// Hash
#define SHA_CH00(x, y, z) (((x) & ((y) ^ (z))) ^ (z))
#define SHA_MAJ0(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define SHA_PARI(x, y, z)  ((x) ^  (y) ^ (z))

// Define the SHA shift, rotate left and rotate right macros
#define SHA_SHRI(b, w)  (((u64)(w)) >> (b))
#define SHA_ROTR(b, w) ((((u64)(w)) >> (b)) | (((u64)(w)) << (64 - (b))))

// Define the SHA SIGMA and sigma macros
#define SHA_S0(w) (SHA_ROTR(28, w) ^ SHA_ROTR(34, w) ^ SHA_ROTR(39, w))
#define SHA_S1(w) (SHA_ROTR(14, w) ^ SHA_ROTR(18, w) ^ SHA_ROTR(41, w))
#define SHA_s0(w) (SHA_ROTR( 1, w) ^ SHA_ROTR( 8, w) ^ SHA_SHRI( 7, w))
#define SHA_s1(w) (SHA_ROTR(19, w) ^ SHA_ROTR(61, w) ^ SHA_SHRI( 6, w))

// Add "length" to the length. Set Corrupted when overflow has occurred.
#define SHA_L(c) (++c->len_hi == 0) ? SHA_ITL : (c)->corrupt
#define SHA_T(c, l) c->corrupt = ((c->len_lo += l) < 0)
#define SHA_ADDL(c, l) (SHA_T(c, l) && SHA_L(c))

// Lightciphers
#define NB 4
#define NK 8
#define NR 14
#define NB4 NB * 4
#define NK4 NK * 4
#define NBR1 NB * (NR + 1)
#define BBL 4 * NB * sizeof(b08)

// Lightcrypto
#define BLOCK 1024

// Lighthash
// These constants hold size information for each of the SHA hashing operations
#define SHA_BLK_SZ 128                           // SHA Message Block Size
#define SHA_HSH_SZ 64                            // SHA Hash Size
#define SHA_HSH_SB 512                           // SHA Hash Size Bits

// All SHA functions return one of these values.
#define SHA_OK 0                                 // Success
#define SHA_NULL 1                               // Null pointer parameter
#define SHA_ITL 2                                // Input data too long
#define SHA_ERR 3                                // State error
#define SHA_BAD 4                                // passed a bad parameter

#define length(x) (sizeof(x) - 1)

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
typedef struct {u64 a, b, c, d;} prng_t;

static u64 curve_p[DI] = {
  0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe,
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static u64 curve_b[DI] = {
  0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4};
static pt curve_g      = {{
  0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38,
  0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537},
  {0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0,
  0xf8f41dbd289a147c, 0x5d9e98bf9292dc29, 0x3617de4a96262c6f}};
static u64 curve_n[DI] = {
  0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static prng_t prng_ctx;
#endif
