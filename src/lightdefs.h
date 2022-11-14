//                                                                            //
#ifndef LIGHTDEFS_H
#define LIGHTDEFS_H 1

#include <stdint.h>

typedef int8_t i08;
typedef uint8_t u08;
typedef const char cc;
typedef unsigned int ui;
typedef unsigned char b08;
typedef const uint8_t cu8;
typedef unsigned __int128 u128;
typedef const unsigned char cuc;
typedef long long unsigned int u64;

typedef uint64_t bit[571];
typedef uint64_t sig[72];

// VSH
typedef struct keys key;
typedef struct header head;
typedef struct sockaddr sock;
typedef struct sockaddr_in sock_in;

// SSL
#define BLOCK 1024
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
#define SHA_ROTR(b, w) ((((u64)(w)) >> (b)) | (((u64)(w)) << (64-(b))))

// Define the SHA SIGMA and sigma macros
#define SHA_S0(w) (SHA_ROTR(28, w) ^ SHA_ROTR(34, w) ^ SHA_ROTR(39, w))
#define SHA_S1(w) (SHA_ROTR(14, w) ^ SHA_ROTR(18, w) ^ SHA_ROTR(41, w))
#define SHA_s0(w) (SHA_ROTR( 1, w) ^ SHA_ROTR( 8, w) ^ SHA_SHRI( 7, w))
#define SHA_s1(w) (SHA_ROTR(19, w) ^ SHA_ROTR(61, w) ^ SHA_SHRI( 6, w))

// Add "length" to the length. Set Corrupted when overflow has occurred.
#define SHA_L(c) (++c->len_hi == 0) ? sha_itl : (c)->corrupt
#define SHA_T(c, l) c->corrupt = ((c->len_lo += l) < 0)
#define SHA_AddLength(c, l) (SHA_T(c, l) && SHA_L(c))

// VSH Structs
struct header {u64 len, ver, g, p;};
struct keys {u64 publ, priv, shar;};

// Keys
#define BT 8
#define KB 48
#define KB2 KB * 2
#define DI (KB / BT)
#define DI2 (DI * 2)
#define EVEN(p) (!(p[0] & 1))
typedef struct pt {u64 x[DI], y[DI];} pt;

static u64 curve_p[DI] = {0x00000000ffffffff, 0xffffffff00000000,
  0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static u64 curve_b[DI] = {0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d,
  0x0314088f5013875a, 0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4};
static pt curve_g      = {{0x3a545e3872760ab7, 0x5502f25dbf55296c,
  0x59f741e082542a38, 0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537},
  {0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
  0x5d9e98bf9292dc29, 0x3617de4a96262c6f}};
static u64 curve_n[DI] = {0xecec196accc52973, 0x581a0db248b0a77a,
  0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};

typedef struct {u64 a, b, c, d;} prng_t;
static prng_t prng_ctx;
#endif
