//                                                                            //
#ifndef LIGHTDEFS_H
#define LIGHTDEFS_H 1

#include <stdint.h>

typedef int8_t i08;
typedef uint8_t u08;
typedef unsigned int ui;
typedef unsigned char b08;
typedef const uint8_t cu8;
typedef unsigned __int128 u128;
typedef long long unsigned int u64;

typedef uint64_t bit[571];
typedef uint64_t sig[72];

// VSH
typedef struct keys key;
typedef struct header head;
typedef struct sockaddr sock;
typedef struct sockaddr_in sock_in;

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

extern const char hexdigits[];
extern const u08 masks[8];
extern const u08 markbit[8];

// Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5
extern const u64 SHA_H0[];
extern const u64 SHA_K[80];

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

// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) ((n % m)+m) % m
#endif
