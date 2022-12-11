//                                                                            //
#ifndef DEFS_H
#define DEFS_H 1

// Only defines here, no typedefs
#define i08 int8_t
#define u08 uint8_t
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
#define SHA_L(c) (++c->len_hi == 0) ? sha_itl : (c)->corrupt
#define SHA_T(c, l) c->corrupt = ((c->len_lo += l) < 0)
#define SHA_AddLength(c, l) (SHA_T(c, l) && SHA_L(c))
#endif
