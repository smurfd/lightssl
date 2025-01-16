// Auth: smurfd, 2024 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "lightaes.h"

// if (a == 1) {b = 3;} else {b = 4;} ==
// b = (a == 1) ? 3 : 4; // way faster than a if-statement
static const uint8_t SBOX[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t INV_SBOX[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
// TODO: SLOW

//
// Convert 4 bytes to a word
static inline uint32_t bytes2word(const uint8_t *b) {
  return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
}

//
// Convert a word to 4 bytes
static inline void word2bytes(uint8_t *b, const uint32_t w) {
  b[0] = (w >> 24) & 0xff;
  b[1] = (w >> 16) & 0xff;
  b[2] = (w >> 8) & 0xff;
  b[3] = (w >> 0) & 0xff;
}

//
// Used to manage 4.1 & 4.2 addition and multiplication
static inline uint8_t gm2(const uint8_t b) {
  return ((b << 1) ^ (0x1b & ((b >> 7) * 0xff))) & 0xff;
}

//
// Substitue a word using SBox
static inline uint32_t subword(const uint32_t w) {
  uint8_t b[4], s[4];
  word2bytes(b, w);
  s[0] = SBOX[b[0]];
  s[1] = SBOX[b[1]];
  s[2] = SBOX[b[2]];
  s[3] = SBOX[b[3]];
  return bytes2word(s);
}

//
// Rotate word x steps
static inline uint32_t rolx(const uint32_t w, const uint32_t x) {
  return ((w << x) | (w >> (32 - x))) & 0xffffffff;
}

static inline void expandnextkeyA(uint32_t *k, const uint32_t *key0, const uint32_t *key1, const uint8_t rcon) {
  uint32_t w[8] = {0};
  memcpy(w + 0, key0, KEYSIZE1);
  memcpy(w + 4, key1, KEYSIZE1);
  uint32_t sw = subword(rolx(w[7], 8)), rw = (rcon << 24), t = sw ^ rw;
  k[0] = w[0] ^ t;
  k[1] = w[1] ^ w[0] ^ t;
  k[2] = w[2] ^ w[1] ^ w[0] ^ t;
  k[3] = w[3] ^ w[2] ^ w[1] ^ w[0] ^ t;
}

static inline void expandnextkeyB(uint32_t *k, const uint32_t *key0, const uint32_t *key1) {
  uint32_t w[8] = {0};
  memcpy(w + 0, key0, KEYSIZE1);
  memcpy(w + 4, key1, KEYSIZE1);
  uint32_t t = subword(w[7]);
  k[0] = w[0] ^ t;
  k[1] = w[1] ^ w[0] ^ t;
  k[2] = w[2] ^ w[1] ^ w[0] ^ t;
  k[3] = w[3] ^ w[2] ^ w[1] ^ w[0] ^ t;
}

//
// Get the RCON constant
static inline uint8_t getrcon(const uint8_t round) {
  uint8_t rcon = 0x8d;
  for (int i = 0; i < round; i++) {
    rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7))) & 0xff;
  }
  return rcon;
}

//
// 5.2
// KEYEXPANSION() is a routine that is applied to the key to generate 4 ∗ (Nr + 1) words. Thus, four words are generated for each of the Nr + 1
// applications of ADDROUNDKEY() within the specifcation of CIPHER(), as described in Section 5.1.4. The output of the routine consists of a
// linear array of words, denoted by w[i], where i is in the range 0 ≤ i < 4 ∗ (Nr + 1)
static inline void keyexpansion(uint32_t *rk, const uint32_t *key) {
  uint32_t ktmp[4], rk1[64], rk2[64], rk3[64], co1 = 4, co2 = 0, rkco = 8;
  memcpy(rk1, key + 0, KEYSIZE1);
  memcpy(rk2, key + 4, KEYSIZE1);
  memcpy(rk, key, 8 * sizeof(uint32_t));
  for (uint8_t i = 0; i < 12; i++) { // 14 number of rounds - 2
    expandnextkeyA(ktmp, rk1 + co2, rk2 + co2, getrcon(i + 1));
    memcpy(rk1 + co1, ktmp, KEYSIZE1);
    memcpy(rk3 + co2, ktmp, KEYSIZE1);
    expandnextkeyB(ktmp, rk2 + co2, rk3 + co2);
    memcpy(rk2 + co1, ktmp, KEYSIZE1);
    memcpy(rk + rkco + 0, rk3 + co2, KEYSIZE1);
    memcpy(rk + rkco + 4, rk2 + co1, KEYSIZE1);
    co1+=4; co2+=4; rkco+=8;
  }
  expandnextkeyA(ktmp, rk1 + co1, rk2 + co1, getrcon(7));
  memcpy(rk + (rkco - 8), ktmp, KEYSIZE1);
}

static inline uint32_t mixword(uint32_t w) {
  uint8_t b[4] = {0}, mb[4] = {0};
  word2bytes(b, w);
  mb[0] = gm2(b[0]) ^ gm2(b[1]) ^ b[1] ^ b[2] ^ b[3];
  mb[1] = b[0] ^ gm2(b[1]) ^ gm2(b[2]) ^ b[2] ^ b[3];
  mb[2] = b[0] ^ b[1] ^ gm2(b[2]) ^ gm2(b[3]) ^ b[3];
  mb[3] = gm2(b[0]) ^ b[0] ^ b[1] ^ b[2] ^ gm2(b[3]);
  return bytes2word(mb);
}

//
// 5.1.1
// SUBBYTES() is an invertible, non-linear transformation of the state in which a substitution table, called an S-box, is applied independently to
// each byte in the state. The AES S-box is denoted by SBOX().
static inline void subbytes(uint32_t *ret, const uint32_t *block) {
  ret[0] = subword(block[0]);
  ret[1] = subword(block[1]);
  ret[2] = subword(block[2]);
  ret[3] = subword(block[3]);
}

//
// 5.1.2
// SHIFTROWS() is a transformation of the state in which the bytes in the last three rows of the state are cyclically shifted.
static inline void shiftrows(uint32_t *ret, const uint32_t *block) {
  uint8_t c0[4], c1[4], c2[4], c3[4], ctmp[4];
  word2bytes(c0, block[0]);
  word2bytes(c1, block[1]);
  word2bytes(c2, block[2]);
  word2bytes(c3, block[3]);
  ctmp[0] = c0[0]; ctmp[1] = c1[1]; ctmp[2] = c2[2]; ctmp[3] = c3[3];
  ret[0] = bytes2word(ctmp);
  ctmp[0] = c1[0]; ctmp[1] = c2[1]; ctmp[2] = c3[2]; ctmp[3] = c0[3];
  ret[1] = bytes2word(ctmp);
  ctmp[0] = c2[0]; ctmp[1] = c3[1]; ctmp[2] = c0[2]; ctmp[3] = c1[3];
  ret[2] = bytes2word(ctmp);
  ctmp[0] = c3[0]; ctmp[1] = c0[1]; ctmp[2] = c1[2]; ctmp[3] = c2[3];
  ret[3] = bytes2word(ctmp);
}

//
// 5.1.3
// MIXCOLUMNS() is a transformation of the state that multiplies each of the four columns of the state by a single fxed matrix,
// as described in Section 4.3
static inline void mixcolumns(uint32_t *ret, const uint32_t *block) {
  ret[0] = mixword(block[0]);
  ret[1] = mixword(block[1]);
  ret[2] = mixword(block[2]);
  ret[3] = mixword(block[3]);
}

//
// 5.1.4
// ADDROUNDKEY() is a transformation of the state in which a round key is combined with the state by applying the bitwise XOR operation.
// In particular, each round key consists of four words from the key schedule (described in Section 5.2),
// each of which is combined with a column of the state
static inline void addroundkey(uint32_t *ret, const uint32_t *key, const uint32_t *block) {
  ret[0] = block[0] ^ key[0];
  ret[1] = block[1] ^ key[1];
  ret[2] = block[2] ^ key[2];
  ret[3] = block[3] ^ key[3];
}

//
// Substitute a word using SBox inverse
static inline uint32_t inv_subword(const uint32_t w) {
  uint8_t b[4], s[4];
  word2bytes(b, w);
  s[0] = INV_SBOX[b[0]];
  s[1] = INV_SBOX[b[1]];
  s[2] = INV_SBOX[b[2]];
  s[3] = INV_SBOX[b[3]];
  return bytes2word(s);
}

static inline uint32_t inv_mixword(uint32_t w) {
  uint8_t b[4] = {0}, mb[4] = {0};
  word2bytes(b, w);
  // gm14(b0) ^ gm11(b1) ^ gm13(b2) ^ gm09(b3)
  mb[0] = (gm2(gm2(gm2(b[0]))) ^ gm2(gm2(b[0])) ^ gm2(b[0])) ^ (gm2(gm2(gm2(b[1]))) ^ gm2(b[1]) ^ b[1]) ^ \
  (gm2(gm2(gm2(b[2]))) ^ gm2(gm2(b[2])) ^ b[2]) ^ (gm2(gm2(gm2(b[3]))) ^ b[3]);
  // gm09(b0) ^ gm14(b1) ^ gm11(b2) ^ gm13(b3)
  mb[1] = (gm2(gm2(gm2(b[0]))) ^ b[0]) ^ (gm2(gm2(gm2(b[1]))) ^ gm2(gm2(b[1])) ^ gm2(b[1])) ^ \
  (gm2(gm2(gm2(b[2]))) ^ gm2(b[2]) ^ b[2]) ^ (gm2(gm2(gm2(b[3]))) ^ gm2(gm2(b[3])) ^ b[3]);
  // gm13(b0) ^ gm09(b1) ^ gm14(b2) ^ gm11(b3)
  mb[2] = (gm2(gm2(gm2(b[0]))) ^ gm2(gm2(b[0])) ^ b[0]) ^ (gm2(gm2(gm2(b[1]))) ^ b[1]) ^ \
  (gm2(gm2(gm2(b[2]))) ^ gm2(gm2(b[2])) ^ gm2(b[2])) ^ (gm2(gm2(gm2(b[3]))) ^ gm2(b[3]) ^ b[3]);
  // gm11(b0) ^ gm13(b1) ^ gm09(b2) ^ gm14(b3)
  mb[3] = (gm2(gm2(gm2(b[0]))) ^ gm2(b[0]) ^ b[0]) ^ (gm2(gm2(gm2(b[1]))) ^ gm2(gm2(b[1])) ^ b[1]) ^ \
  (gm2(gm2(gm2(b[2]))) ^ b[2]) ^ (gm2(gm2(gm2(b[3]))) ^ gm2(gm2(b[3])) ^ gm2(b[3]));
  return bytes2word(mb);
}

//
// 5.3.1
// INVSHIFTROWS() is the inverse of SHIFROWS()
static inline void inv_shiftrows(uint32_t *ret, const uint32_t *block) {
  uint8_t c0[4], c1[4], c2[4], c3[4], ctmp[4];
  word2bytes(c0, block[0]);
  word2bytes(c1, block[1]);
  word2bytes(c2, block[2]);
  word2bytes(c3, block[3]);
  ctmp[0] = c0[0]; ctmp[1] = c3[1]; ctmp[2] = c2[2]; ctmp[3] = c1[3];
  ret[0] = bytes2word(ctmp);
  ctmp[0] = c1[0]; ctmp[1] = c0[1]; ctmp[2] = c3[2]; ctmp[3] = c2[3];
  ret[1] = bytes2word(ctmp);
  ctmp[0] = c2[0]; ctmp[1] = c1[1]; ctmp[2] = c0[2]; ctmp[3] = c3[3];
  ret[2] = bytes2word(ctmp);
  ctmp[0] = c3[0]; ctmp[1] = c2[1]; ctmp[2] = c1[2]; ctmp[3] = c0[3];
  ret[3] = bytes2word(ctmp);
}

//
// 5.3.2
// INVSUBBYTES() is the inverse of SUBBYTES(), in which the inverse of SBOX(), denoted by INVSBOX(), is applied to each byte of the state.
// INVSBOX() is derived from Table 4 by switching the roles of inputs and outputs, as presented in Table 6
static inline void inv_subbytes(uint32_t *ret, const uint32_t *block) {
  ret[0] = inv_subword(block[0]);
  ret[1] = inv_subword(block[1]);
  ret[2] = inv_subword(block[2]);
  ret[3] = inv_subword(block[3]);
}

//
// 5.3.3
// INVMIXCOLUMNS() is the inverse of MIXCOLUMNS(). In particular, INVMIXCOLUMNS() multiplies each of the four columns of the state by a single
// fixed matrix, as described in Section 4.3
static inline void inv_mixcolumns(uint32_t *ret, const uint32_t *block) {
  ret[0] = inv_mixword(block[0]);
  ret[1] = inv_mixword(block[1]);
  ret[2] = inv_mixword(block[2]);
  ret[3] = inv_mixword(block[3]);
}

//
// 5.1
// The rounds in the specifcation of CIPHER() are composed of the following four byte-oriented transformations on the state:
// SUBBYTES() applies a substitution table (S-box) to each byte.
// SHIFTROWS() shifts rows of the state array by different offsets.
// MIXCOLUMNS() mixes the data within each column of the state array.
// ADDROUNDKEY() combines a round key with the state.
// The four transformations are specifed in Sections 5.1.1–5.1.4.
void cipher(uint32_t *ret, const uint32_t *key, const uint32_t *block) {
  uint32_t rk[128], tmpb1[4] = {0}, tmpb2[4] = {0}, tmpb3[4] = {0}, tmpb4[4] = {0};
  keyexpansion(rk, key);
  addroundkey(tmpb4, rk, block);
  for (int i = 1; i < 14; i++) {
    subbytes(tmpb1, tmpb4);
    shiftrows(tmpb2, tmpb1);
    mixcolumns(tmpb3, tmpb2);
    addroundkey(tmpb4, rk + (i * 4), tmpb3);
  }
  subbytes(tmpb1, tmpb4);
  shiftrows(tmpb2, tmpb1);
  addroundkey(ret, rk + (14 * 4), tmpb2);
}

//
// 5.3
// To implement INVCIPHER(), the transformations in the specifcation of CIPHER() (Section 5.1) are inverted and executed in reverse order.
// The inverted transformations of the state — denoted by INVSHIFTROWS(), INVSUBBYTES(), INVMIXCOLUMNS(), and ADDROUNDKEY() — are
// described in Sections 5.3.1–5.3.4.
void inv_cipher(uint32_t *ret, const uint32_t *key, const uint32_t *block) {
  uint32_t rk[128], tmpb1[4] = {0}, tmpb2[4] = {0}, tmpb3[4] = {0}, tmpb4[4] = {0};
  keyexpansion(rk, key);
  addroundkey(tmpb1, rk + (14 * 4), block);
  inv_shiftrows(tmpb2, tmpb1);
  inv_subbytes(tmpb4, tmpb2);
  for (int i = 13; i >= 1; i--) { // 14 rounds but one already done, so -1
    addroundkey(tmpb1, rk + (i * 4), tmpb4);
    inv_mixcolumns(tmpb2, tmpb1);
    inv_shiftrows(tmpb3, tmpb2);
    inv_subbytes(tmpb4, tmpb3);
  }
  addroundkey(ret, rk, tmpb4);
}

static inline void big_endian_uint32(uint8_t *a, uint32_t value) {
  a[0] = (value >> 24) & 0xff;
  a[1] = (value >> 16) & 0xff;
  a[2] = (value >> 8) & 0xff;
  a[3] = (value >> 0) & 0xff;
}

static inline uint32_t read_big_endian_uint32(const uint8_t *a) {
  return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void xorblock(uint8_t *Z, const uint8_t *X, const uint8_t *Y) {
  for (int i = 0; i < 16; i++) {
    Z[i] = (X[i] ^ Y[i]);
  }
}

static inline void xorblock32bit(uint32_t *Z, const uint32_t *X, const uint32_t *Y) {
  for (int i = 0; i < 8; i++) {
    Z[i] = (X[i] ^ Y[i]);
  }
}

// AES GCM
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf

// 6.2
// Incrementing Function
// For a positive integer s and a bit string X such that len(X)≥s, let the s-bit incrementing function, denoted incs(X)
static inline void inc32(uint8_t *wrd) {
  uint32_t value = read_big_endian_uint32((wrd + (16 - 4)));
  value++;
  big_endian_uint32((wrd + (16 - 4)), value);
}

// 6.3
// Algorithm 1: X • Y
// MULTIPLICATION Function
// Multiplication Operation on Blocks
static inline void GCM_MULTIPLY(uint8_t *BITZ, const uint8_t *BITX, const uint8_t *BITY) {
  u64 Z, R=0xe1000000U, t;
  uint8_t b8[16] = {0}, b0, b1, b2, b3, b4, b5, b6, b7;
  uint32_t bz[16] = {0};
  // Pre-calculate for speed
  for (int i = 0; i < 16; i++) {
    bz[i] = BITX[i] ^ BITY[i];
    b0 = BITX[i] & 128, b1 = BITX[i] & 64, b2 = BITX[i] & 32, b3 = BITX[i] & 16, b4 = BITX[i] & 8, b5 = BITX[i] & 4, b6 = BITX[i] & 2, b7 = BITX[i] & 1;
    b8[i] = (b0 || b1 || b2 || b3 || b4 || b5 || b6 || b7);
  }
  for (int i = 0; i < 16; i++) {
    BITZ[i] = (b8[i]) ? bz[i] : BITZ[i];
    t = R & Z;
    R <<= 1;
    R = (t & 0x10000000U) ? R ^ 0x87 : R;
    Z = t;
    for (int j = 0; j < 16; j++) {
      BITZ[j] = (BITZ[j] >> (8 * j)) & 0xFF;
    }
  }
}

static inline void GCM_MULTIPLY32bit(uint32_t *BITZ, const uint32_t *BITX, const uint32_t *BITY) {
  u64 Z, R=0xe1000000U, t;
  uint8_t b8[8] = {0}, b0, b1, b2, b3, b4, b5, b6, b7;
  uint32_t bz[8] = {0};
  // Pre-calculate for speed
  for (int i = 0; i < 8; i++) {
    bz[i] = BITX[i] ^ BITY[i];
    b0 = BITX[i] & 128, b1 = BITX[i] & 64, b2 = BITX[i] & 32, b3 = BITX[i] & 16, b4 = BITX[i] & 8, b5 = BITX[i] & 4, b6 = BITX[i] & 2, b7 = BITX[i] & 1;
    b8[i] = (b0 || b1 || b2 || b3 || b4 || b5 || b6 || b7);
  }
  for (int i = 0; i < 8; i++) {
    BITZ[i] = (b8[i]) ? bz[i] : BITZ[i]; // way faster than a if-statement
    t = R & Z;
    R <<= 1;
    R = (t & 0x10000000U) ? R ^ 0x87 : R;
    Z = t;
    for (int j = 0; j < 8; j++) {
      BITZ[j] = (BITZ[j] >> (8 * j)) & 0xFF;
    }
  }
}

// 6.4
// Algorithm 2: GHASHh (X)
// GHASH Function
// In effect, the GHASH function calculates X1•Hm ⊕ X2•Hm-1 ⊕ ... ⊕ Xm-1•H2 ⊕ Xm•H. Ref. [6] describes methods for optimizing
// implementations of GHASH in both hardware and software
static inline void GHASH(uint8_t *Y, const uint8_t *X, const uint8_t *H, uint32_t lenx) {
  uint8_t tmp[32] = {0};
  memset(Y, 0, 16 * sizeof(uint8_t));
  for (int i = 1; i < (lenx / 16) + 1; i++) {
    xorblock(tmp, Y, X + ((i - 1) * 16));
    GCM_MULTIPLY(Y, tmp, H);
  }
}

static inline void GHASH32bit(uint32_t *Y, const uint32_t *X, const uint32_t *H, uint32_t lenx) {
  uint32_t tmp[32] = {0};
  memset(Y, 0, 8 * sizeof(uint32_t));
  for (int i = 1; i < (lenx / 16) + 1; i++) {
    xorblock32bit(tmp, Y, X + ((i - 1) * 8));
    GCM_MULTIPLY32bit(Y, tmp, H);
  }
}

// 6.5
// Algorithm 3: GCTRk (ICB, X)
// GCTR Function
static inline void GCTR(uint8_t *Y, const uint8_t *ICB, const uint8_t *X, const uint8_t *key, const uint32_t lenx) {
  uint32_t nblocks = lenx / 16, eCB[32] = {0}, CBwrd[32] = {0}, *CBinc = CBwrd;
  uint8_t CB[32] = {0}, plain[32] = {0}, cipB[32] = {0}, eCBbytes[32] = {0}, eCBb[4] = {0}, CBb[4] = {0};
  if (X == NULL) return;
  for (int i = 0; i < 16; i++) CB[i] = ICB[i];
  inc32(CB);
  uint32_t keywrd[32] = {0};
  uint8_t bkey[4] = {0};
  for (int j = 0; j < 32; j+=4) {
    bkey[0] = key[j + 0];
    bkey[1] = key[j + 1];
    bkey[2] = key[j + 2];
    bkey[3] = key[j + 3];
    keywrd[j/4] = bytes2word(bkey);
    CBb[0] = CB[j + 0];
    CBb[1] = CB[j + 1];
    CBb[2] = CB[j + 2];
    CBb[3] = CB[j + 3];
    CBwrd[j/4] = bytes2word(CBb);
  }
  for (int i = 0; i < nblocks; i++) {
    //(((i + 1) * 16) > lenx) ? break;:;
    if (((i + 1) * 16) > lenx) break;
    cipher(eCB, keywrd, CBinc++);
    for (int j = 0; j < 8; j++) {
      word2bytes(eCBb, eCB[j]);
      eCBbytes[(j * 4) + 0] = eCBb[0];
      eCBbytes[(j * 4) + 1] = eCBb[1];
      eCBbytes[(j * 4) + 2] = eCBb[2];
      eCBbytes[(j * 4) + 3] = eCBb[3];
    }
    memcpy(plain, X + (i * 16), 16);
    xorblock(cipB, eCBbytes, plain);
    memcpy(Y + (i * 16), cipB, 16);
  }
  uint32_t fl = lenx - (nblocks * 16);
  cipher(eCB, keywrd, CBinc++);
  for (int j = 0; j < 8; j++) {
    word2bytes(eCBb, eCB[j]);
    eCBbytes[(j * 4) + 0] = eCBb[0];
    eCBbytes[(j * 4) + 1] = eCBb[1];
    eCBbytes[(j * 4) + 2] = eCBb[2];
    eCBbytes[(j * 4) + 3] = eCBb[3];
  }
  memcpy(plain, X + (nblocks * 16), fl);
  xorblock(cipB, eCBbytes, plain);
  memcpy(Y + (nblocks * 16), cipB, fl);
}

static inline void GCTR32bit(uint32_t *Y, const uint32_t *ICB, const uint32_t *X, const uint32_t *key, const uint32_t lenx) {
  uint32_t nblocks = lenx / 8, eCB[32] = {0}, CBwrd[32] = {0}, *CBinc = CBwrd, CB[32] = {0}, plain[32]= {0}, cipB[32] = {0};
  if (X == NULL) return;
  for (int i = 0; i < 8; i++) CB[i] = ICB[i];
  (*CB)++;
  for (int i = 0; i < nblocks; i++) {
    if (((i + 1) * 8) > lenx) break;
    cipher(eCB, key, CBinc++);
    memcpy(plain, X + (i * 8), 8 * sizeof(uint32_t));
    xorblock32bit(cipB, eCB, plain);
    memcpy(Y + (i * 8), cipB, 8 * sizeof(uint32_t));
  }
  uint32_t fl = lenx - (nblocks * 8);
  cipher(eCB, key, CBinc++);
  memcpy(plain, X + (nblocks * 8), fl);
  xorblock32bit(cipB, eCB, plain);
  memcpy(Y + (nblocks * 8), cipB, fl);
}

// 7.1
// Algorithm 4: GCM-AEK (IV, P, A)
// Algorithm for the Authenticated Encryption Function
void gcm_ciphertag(uint8_t *c, uint8_t *t, const uint8_t *key, uint8_t *iv, const uint8_t *plain, const uint8_t *aad, const u64 lenx) {
  u64 aadlen = 12, ivlen = 32, clen = 32;
  if (lenx > MAXPLAIN || aadlen > MAXAAD || ivlen > MAXIV || ivlen < 1) return;
  uint32_t keywrd[32] = {0}, hwrd[32] = {0}, hkwrd[32] = {0}, pc = (16 * (clen / 16)) - clen, pa = (16 * (aadlen / 16)) - aadlen;
  uint32_t bhlen = aadlen + (4 * sizeof(uint32_t)) + clen;
  uint8_t *bh = malloc(bhlen), hk[32] = {0}, h[32] = {0}, j0[16] = {0}, hb[32] = {0}, bkey[4] = {0}, bbh[4] = {0}, bhk[4] = {0};
  memset(bh, 0, bhlen * sizeof(uint8_t));
  for (int j = 0; j < 32; j+=4) {
    bkey[0] = key[j + 0];
    bkey[1] = key[j + 1];
    bkey[2] = key[j + 2];
    bkey[3] = key[j + 3];
    keywrd[j/4] = bytes2word(bkey);
    bbh[0] = h[j + 0];
    bbh[1] = h[j + 1];
    bbh[2] = h[j + 2];
    bbh[3] = h[j + 3];
    hwrd[j/4] = bytes2word(bbh);
    bhk[0] = hk[j + 0];
    bhk[1] = hk[j + 1];
    bhk[2] = hk[j + 2];
    bhk[3] = hk[j + 3];
    hkwrd[j/4] = bytes2word(bhk);
  }
  cipher(hkwrd, keywrd, hwrd);
  if (ivlen == 12) { // when does this happen?!
    uint8_t b0[4] = {0x00, 0x00, 0x00, 0x01};
    memcpy(iv + ivlen, b0, 4);
  } else {
    uint32_t pl = (16 * (ivlen / 16)) - ivlen;
    uint8_t *bs = malloc((ivlen + pl + (2 * sizeof(uint32_t))) * sizeof(uint8_t));
    memset(bs, 0, ivlen + pl + (2 * sizeof(uint32_t)));
    memcpy(bs, iv, ivlen);
    memcpy(bs + ivlen, &pl, sizeof(uint32_t));
    memcpy(bs + ivlen + sizeof(uint32_t), &ivlen, sizeof(uint32_t));
    GHASH(j0, bs, hk, ivlen + (2 * sizeof(uint32_t)));
    free(bs);
  }
  inc32(j0);
  (*j0)++;
  GCTR(c, j0, plain, key, lenx);
  memcpy(bh, aad, aadlen);
  memcpy(bh + aadlen, &pc, sizeof(uint32_t));
  memcpy(bh + aadlen + sizeof(uint32_t), c, clen);
  memcpy(bh + aadlen + sizeof(uint32_t) + clen, &pa, sizeof(uint32_t));
  memcpy(bh + aadlen + (2 * sizeof(uint32_t)) + clen, &aadlen, sizeof(uint32_t));
  memcpy(bh + aadlen + (3 * sizeof(uint32_t)) + clen, &clen, sizeof(uint32_t));
  GHASH(hb, bh, hk, bhlen);
  GCTR(t, j0, hb, key, 12); // 12 = tag length?
  free(bh);
}

void gcm_ciphertag32bit(uint32_t *c, uint32_t *t, const uint32_t *key, uint32_t *iv, const uint32_t *plain, const uint32_t *aad, const u64 lenx) {
  u64 aadlen = 12, ivlen = 8, clen = 8;
  if (lenx > MAXPLAIN || aadlen > MAXAAD || ivlen > MAXIV || ivlen < 1) return;
  uint32_t pc = (8 * (clen / 8)) - clen, pa = (8 * (aadlen / 8)) - aadlen;
  uint32_t bhlen = aadlen + (4 * sizeof(uint32_t)) + clen, hk[32] = {0}, h[32] = {0}, j0[32] = {0};
  uint32_t *bh = malloc(bhlen * sizeof(uint32_t)), hb[32] = {0};
  memset(bh, 0, bhlen * sizeof(uint32_t));
  cipher(hk, key, h);
  if (ivlen == 12) { // when does this happen?!
    uint32_t b0[4] = {0x00000000, 0x00000000, 0x00000000, 0x000000000001};
    memcpy(iv + ivlen, b0, 4*sizeof(uint32_t));
  } else {
    uint32_t pl = (16 * (ivlen / 16)) - ivlen;
    uint32_t *bs = malloc((ivlen + pl + (2 * sizeof(uint32_t))) * sizeof(uint32_t));
    memset(bs, 0, (ivlen + pl + (2 * sizeof(uint32_t))) * sizeof(uint32_t));
    memcpy(bs, iv, ivlen);
    memcpy(bs + ivlen, &pl, sizeof(uint32_t));
    memcpy(bs + ivlen + sizeof(uint32_t), &ivlen, sizeof(uint32_t));
    GHASH32bit(j0, bs, hk, ivlen + (2 * sizeof(uint32_t)));
    free(bs);
  }
  (*j0)++;
  (*j0)++;
  GCTR32bit(c, j0, plain, key, lenx);
  memcpy(bh, aad, aadlen);
  memcpy(bh + aadlen, &pc, sizeof(uint32_t));
  memcpy(bh + aadlen + sizeof(uint32_t), c, clen);
  memcpy(bh + aadlen + sizeof(uint32_t) + clen, &pa, sizeof(uint32_t));
  memcpy(bh + aadlen + (2 * sizeof(uint32_t)) + clen, &aadlen, sizeof(uint32_t));
  memcpy(bh + aadlen + (3 * sizeof(uint32_t)) + clen, &clen, sizeof(uint32_t));
  GHASH32bit(hb, bh, hk, bhlen);
  GCTR32bit(t, j0, hb, key, 12); // 12 = tag length?
  free(bh);
}

// 7.2
// Algorithm 5: GCM-ADK (IV, C, A, T)
// Algorithm for the Authenticated Decryption Function
void gcm_inv_ciphertag(uint8_t *plain, uint8_t *t, const uint8_t *key, const uint8_t *iv, const uint8_t *c, const uint8_t *aad, const uint8_t *tag) {
  u64 aadlen = 12, ivlen = 32, clen = 32;
  if (clen > MAXPLAIN || aadlen > MAXAAD || ivlen > MAXIV || ivlen < 1) return;
  uint32_t pc = (16 * (clen / 16)) - clen, pa = (16 * (aadlen / 16)) - aadlen, bhlen = aadlen + (4 * sizeof(uint32_t)) + clen;
  uint32_t keywrd[32] = {0}, hwrd[32] = {0}, hkwrd[32] = {0};
  uint8_t bkey[4] = {0}, bbh[4] = {0}, bhk[4] = {0}, hk[32] = {0}, h[32] = {0}, j0[32] = {0}, hb[32] = {0}, *bh = malloc(bhlen);
  memset(bh, 0, bhlen * sizeof(uint8_t));
  for (int j = 0; j < 32; j+=4) {
    bkey[0] = key[j + 0];
    bkey[1] = key[j + 1];
    bkey[2] = key[j + 2];
    bkey[3] = key[j + 3];
    keywrd[j/4] = bytes2word(bkey);
    bbh[0] = h[j + 0];
    bbh[1] = h[j + 1];
    bbh[2] = h[j + 2];
    bbh[3] = h[j + 3];
    hwrd[j/4] = bytes2word(bbh);
    bhk[0] = hk[j + 0];
    bhk[1] = hk[j + 1];
    bhk[2] = hk[j + 2];
    bhk[3] = hk[j + 3];
    hkwrd[j/4] = bytes2word(bhk);
  }
  cipher(hkwrd, keywrd, hwrd);
  if (ivlen == 12) { // when does this happen?!
    uint8_t b0[4] = {0x00, 0x00, 0x00, 0x01};
    memcpy(j0, iv, ivlen);
    memcpy(j0 + ivlen, b0, 4);
  } else {
    uint32_t pl = (16 * (ivlen / 16)) - ivlen;
    uint8_t *bs = malloc(ivlen + pl + (2 * sizeof(uint32_t)));
    memset(bs, 0, ivlen + pl + (2 * sizeof(uint32_t)));
    memcpy(bs, iv, ivlen);
    memcpy(bs + ivlen, &pl, sizeof(uint32_t));
    memcpy(bs + ivlen + sizeof(uint32_t), &ivlen, sizeof(uint32_t));
    GHASH(j0, bs, hk, ivlen + (2 * sizeof(uint32_t)));
    free(bs);
  }
  inc32(j0);
  (*j0)++;
  GCTR(plain, j0, c, key, clen);
  memcpy(bh, aad, aadlen);
  memcpy(bh + aadlen, &pc, sizeof(uint32_t));
  memcpy(bh + aadlen + sizeof(uint32_t), c, clen);
  memcpy(bh + aadlen + sizeof(uint32_t) + clen, &pa, sizeof(uint32_t));
  memcpy(bh + aadlen + (2 * sizeof(uint32_t)) + clen, &aadlen, sizeof(uint32_t));
  memcpy(bh + aadlen + (3 * sizeof(uint32_t)) + clen, &clen, sizeof(uint32_t));
  GHASH(hb, bh, hk, bhlen);
  GCTR(t, j0, hb, key, 12); // 12 = tag length?
  assert(memcmp(t, tag, 16 * sizeof(uint8_t)) == 0);
  free(bh);
}

void gcm_inv_ciphertag32bit(uint32_t *plain, uint32_t *t, const uint32_t *key, const uint32_t *iv, const uint32_t *c, const uint32_t *aad, const uint32_t *tag) {
  u64 aadlen = 12, ivlen = 8, clen = 8;
  if (clen > MAXPLAIN || aadlen > MAXAAD || ivlen > MAXIV || ivlen < 1) return;
  uint32_t pc = (8 * (clen / 8)) - clen, pa = (8 * (aadlen / 8)) - aadlen, bhlen = aadlen + (4 * sizeof(uint32_t)) + clen;
  uint32_t j0[32] = {0}, hk[32] = {0}, h[32] = {0}, hb[32] = {0}, *bh = malloc(bhlen * sizeof(uint32_t));
  memset(bh, 0, bhlen * sizeof(uint32_t));
  cipher(hk, key, h);
  if (ivlen == 12) { // when does this happen?!
    uint32_t b0[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000001};
    memcpy(j0, iv, ivlen * sizeof(uint32_t));
    memcpy(j0 + ivlen, b0, 4 * sizeof(uint32_t));
  } else {
    uint32_t pl = (16 * (ivlen / 16)) - ivlen;
    uint32_t *bs = malloc((ivlen + pl + (2 * sizeof(uint32_t))) * sizeof(uint32_t));
    memset(bs, 0, (ivlen + pl + (2 * sizeof(uint32_t))) * sizeof(uint32_t));
    memcpy(bs, iv, ivlen);
    memcpy(bs + ivlen, &pl, sizeof(uint32_t));
    memcpy(bs + ivlen + sizeof(uint32_t), &ivlen, sizeof(uint32_t));
    GHASH32bit(j0, bs, hk, ivlen + (2 * sizeof(uint32_t)));
    free(bs);
  }
  (*j0)++;
  (*j0)++;
  GCTR32bit(plain, j0, c, key, clen);
  memcpy(bh, aad, aadlen);
  memcpy(bh + aadlen, &pc, sizeof(uint32_t));
  memcpy(bh + aadlen + sizeof(uint32_t), c, clen);
  memcpy(bh + aadlen + sizeof(uint32_t) + clen, &pa, sizeof(uint32_t));
  memcpy(bh + aadlen + (2 * sizeof(uint32_t)) + clen, &aadlen, sizeof(uint32_t));
  memcpy(bh + aadlen + (3 * sizeof(uint32_t)) + clen, &clen, sizeof(uint32_t));
  GHASH32bit(hb, bh, hk, bhlen);
  GCTR32bit(t, j0, hb, key, 12); // 12 = tag length?
  assert(memcmp(t, tag, 8 * sizeof(uint32_t)) == 0);
  free(bh);
}

// Code grabbed from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf and massaged

// good read:
//   https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
//   https://www.cse.wustl.edu/~jain/cse571-11/ftp/l_05aes.pdf
//   https://ie.u-ryukyu.ac.jp/~wada/design04/spec_e.html
//   https://blog.0x7d0.dev/education/how-aes-is-implemented/
//   https://github.com/m3y54m/aes-in-c?tab=readme-ov-file#the-rijndael-key-schedule
//   https://en.wikipedia.org/wiki/Rijndael_S-box
//   https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Galois%20Counter%20Mode%20with%20Secure%20Short%20Tags.pdf
//   https://medium.com/codex/aes-how-the-most-advanced-encryption-actually-works-b6341c44edb9
//   https://networkbuilders.intel.com/docs/networkbuilders/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide-1693300747.pdf
//   https://datatracker.ietf.org/doc/html/rfc8452#appendix-A
//   https://github.com/secworks/aes/blob/master/src/model/python/aes.py
//   https://github.com/p4-team/crypto-commons/blob/master/crypto_commons/symmetrical/aes.py#L243

// AES GCM
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
