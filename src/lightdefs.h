//                                                                            //
#ifndef LIGHTDEFS_H
#define LIGHTDEFS_H 1

#include <stdint.h>

typedef int8_t i08;
typedef uint8_t u08;
typedef const char cc;
typedef unsigned char uc;
typedef unsigned char b08;
typedef const unsigned char cuc;
typedef long long unsigned int u64;

// SSL
#define BYTE 8
#define DIG_SIZE 512 / BYTE
#define SEVENFFF 0x7fffffffffffffff
#define RAND() (rand() & SEVENFFF)
#define SHA512_BLOCK_SIZE 1024 / BYTE

// TLS
#define TLSCIPHER 222
#define TLSVERSION 0x304
#define TLSCIPHERAVAIL 222
#define TLSCOMPRESSION 123

// Hash
#define SHA_Ch(x, y, z)    (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)   (((x) & ((y) | (z))) | ((y) & (z)))
#define SHA_Parity(x, y, z) ((x) ^  (y) ^ (z))

// Define the SHA shift, rotate left and rotate right macros
#define SHA_SHRI(b,w)  (((u64)(w)) >> (b))
#define SHA_ROTR(b,w) ((((u64)(w)) >> (b)) | (((u64)(w)) << (64-(b))))

// Define the SHA SIGMA and sigma macros
#define SHA_S0(w) (SHA_ROTR(28,w) ^ SHA_ROTR(34,w) ^ SHA_ROTR(39,w))
#define SHA_S1(w) (SHA_ROTR(14,w) ^ SHA_ROTR(18,w) ^ SHA_ROTR(41,w))
#define SHA_s0(w) (SHA_ROTR( 1,w) ^ SHA_ROTR( 8,w) ^ SHA_SHRI( 7,w))
#define SHA_s1(w) (SHA_ROTR(19,w) ^ SHA_ROTR(61,w) ^ SHA_SHRI( 6,w))

// Add "length" to the length. Set Corrupted when overflow has occurred.
#define SHA_AddLength(c, l, t)(t = c->len_lo,\
  c->corrupt = ((c->len_lo += l) < t) &&\
  (++c->len_hi == 0) ? sha_itl : (c)->corrupt)

#define RAND64()                                                               \
  ((u64)(RAND()) << 48) ^ ((u64)(RAND()) << 35) ^ ((u64)(RAND()) << 22)        \
    ^ ((u64)(RAND()) << 9) ^ ((u64)(RAND()) >> 4)

#endif
