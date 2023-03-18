//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "lighthash.h"
#include "lightdefs.h"

// Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5
const u64 h0[] = {
  0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,0xA54FF53A5F1D36F1,
  0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B,0x5BE0CD19137E2179};
const u64 k0[80] = {
  0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,0xE9B5DBA58189DBBC,
  0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B,0xAB1C5ED5DA6D8118,
  0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C,0x550C7DC3D5FFB4E2,
  0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,0xC19BF174CF692694,
  0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5,0x240CA1CC77AC9C65,
  0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4,0x76F988DA831153B5,
  0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,0xBF597FC7BEEF0EE4,
  0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F,0x142929670A0E6E70,
  0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED,0x53380D139D95B3DF,
  0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,0x92722C851482353B,
  0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791,0xC76C51A30654BE30,
  0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A,0x106AA07032BBD1B8,
  0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,0x34B0BCB5E19B48A8,
  0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373,0x682E6FF3D6B2B8A3,
  0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72,0x8CC702081A6439EC,
  0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,0xC67178F2E372532B,
  0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E,0xF57D4F7FEE6ED178,
  0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE,0x1B710B35131C471B,
  0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,0x431D67C49C100D4C,
  0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC,0x6C44198C4A475817};
const uint8_t masks[8]    = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE};
const uint8_t markbit[8]  = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
const uint8_t hexdigits[] = "0123456789ABCDEF";

//
// SHA Process message block
static void lhsha_proc_msgblk(ctxs *c) {
  u64 A[8], W[80], t1, t2, t3 = 0;
  int t, t8;

  // Initialize the first 16 words in the array W
  for (t = t8 = 0; t < 16; t++, t8 += 8) {
    for (int i = 0; i < 8; i++)
      t3 |= ((u64)(c->mb[t8 + i]) << (56 - (i * 8)));
    W[t] = t3; t3 = 0;
  }
  for (t = 16; t < 80; t++)
    W[t] = SHA_s1(W[t - 2]) + W[t - 7] + SHA_s0(W[t - 15]) + W[t - 16];
  for (int i = 0; i < 8; i++) {A[i] = c->imh[i];}
  for (t = 0; t < 80; t++) {
    t1 = A[7] + SHA_S1(A[4]) + SHA_CH00(A[4],A[5],A[6]) + k0[t] + W[t];
    t2 = SHA_S0(A[0]) + SHA_MAJ0(A[0], A[1], A[2]);
    for (int i = 7; i >= 0; i--) {if (i != 4 && i != 0) {A[i] = A[i - 1];}
      else if (i == 4) {A[4] = A[3] + t1;}
      else if (i == 0) {A[0] = t1 + t2;}}
  }
  for (int i = 0; i < 8; i++) {c->imh[i] += A[i];}
  c->msg_blk_i = 0;
}

//
// SHA Pad message if needed. Process it. Cont pad 2nd block if needed.
static void lhsha_pad_msg(ctxs *c, uint8_t pad_byte) {
  if (c->msg_blk_i >= (SHA_BLK_SZ - 16)) {
    c->mb[c->msg_blk_i++] = pad_byte;
    while (c->msg_blk_i < SHA_BLK_SZ) c->mb[c->msg_blk_i++] = 0;
    lhsha_proc_msgblk(c);
  } else c->mb[c->msg_blk_i++] = pad_byte;
  while (c->msg_blk_i < (SHA_BLK_SZ - 16)) {c->mb[c->msg_blk_i++] = 0;}
  for (int i = 0; i < 8; i++) {c->mb[112 + i] = (c->len_hi >> (56 - (i*8)));
    c->mb[120 + i] = (c->len_lo >> (56 - (i*8)));}
  lhsha_proc_msgblk(c);
}

//
// SHA Finalize
static void lhsha_finalize(ctxs *c, uint8_t pad_byte) {
  lhsha_pad_msg(c, pad_byte);
  // Clear message
  for (int_least16_t i = 0; i < SHA_BLK_SZ; ++i) {c->mb[i] = 0;}
  c->len_hi = c->len_lo = 0;
  c->compute = 1;
}

//
// SHA Error check
static int lhsha_error(ctxs *c, cuc *msg_arr, uint32_t length, int b) {
  if (!c) return SHA_NULL;
  if (!length) return SHA_OK;
  if (!msg_arr && b == 0) return SHA_NULL;
  if (c->compute) return c->corrupt = SHA_ERR;
  if (c->corrupt) return c->corrupt;
  if (length >= 8 && b == 1) return c->corrupt = SHA_BAD;
  return SHA_OK;
}

//
// SHA Clear
int lhsha_reset(ctxs *c) {
  if (!c) return SHA_NULL;
  c->msg_blk_i = 0;
  c->len_hi = c->len_lo = 0;
  c->compute = 0;
  c->corrupt = SHA_OK;
  for (int i = 0; i < SHA_HSH_SZ / 8; i++) {c->imh[i] = h0[i];}
  return SHA_OK;
}

//
// SHA Input
int lhsha_input(ctxs *c, cuc *msg_arr, uint32_t length) {
  lhsha_error(c, msg_arr, length, 0);
  while (length--) {
    c->mb[c->msg_blk_i++] = *msg_arr;
    if ((SHA_ADDL(c, 8) == SHA_OK) && (c->msg_blk_i == SHA_BLK_SZ))
      lhsha_proc_msgblk(c);
    msg_arr++;
  }
  return c->corrupt;
}

//
// SHA Add final bits
int lhsha_final(ctxs *c, uint8_t msg_bit, uint32_t length) {
  lhsha_error(c, (cuc *)0, length, 1);
  SHA_ADDL(c, length);
  lhsha_finalize(c, (uint8_t)((msg_bit & masks[length]) | markbit[length]));
  return c->corrupt;
}

//
// SHA Get digest
int lhsha_result(ctxs *c, uint8_t msg_dig[SHA_HSH_SZ]) {
  lhsha_error(c, msg_dig, 0, 2);
  if (!c->compute) lhsha_finalize(c, 0x80);
  for (int i = 0; i < SHA_HSH_SZ; ++i) {
    msg_dig[i] = (uint8_t)(c->imh[i>>3] >> 8 * (7 - (i % 8)));
  }
  return SHA_OK;
}

//
// SHA Check if hashvalue matches a predef hexstr and convert to str if s!=NULL
int lhsha_match_to_str(cuc *hashvalue, cc *hexstr, int hashsize, char *s) {
  int j = 0, k, l;

  for (int i = 0; i < hashsize; ++i) {
    k = hexdigits[(hashvalue[i] >> 4) & 0xF]; l = hexdigits[hashvalue[i] & 0xF];
    if (s != NULL) {s[j++] = k; s[j++] = l; s[j]='\0';}
    if (*hexstr++ != k) return 0; if (*hexstr++ != l) return 0;
  }
  return 1;
}

//
// Create a SHA hash from string
void lhnew(cc *in, char* s) {
  uint8_t msg_dig[SHA_HSH_SZ], inn[strlen(in)];
  ctxs sha;

  // Convert char* to uint8_t*
  for (u64 i = 0; i < strlen(in); i++) {inn[i] = (uint8_t)in[i];}
  lhsha_reset(&sha);
  lhsha_input(&sha, inn, strlen(in));
  lhsha_final(&sha, (uint8_t)0, 0);
  lhsha_result(&sha, msg_dig);
  // Convert uint8_t* to char*
  lhsha_match_to_str(msg_dig, s, 64, s);
}

//
// HMAC error check
static int lhhmac_error(ctxh *c) {
  if (!c) return SHA_NULL;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = SHA_ERR;
  return SHA_OK;
}

//
// HMAC initialize Context
int lhhmac_reset(ctxh *c, cuc *key, int key_len) {
  uint8_t k_ipad[SHA_BLK_SZ], tmp[SHA_HSH_SZ], blocksize, hashsize, ret;

  if (!c) return SHA_NULL;
  c->compute = 0;
  c->corrupt = SHA_OK;
  blocksize = c->blk_size = SHA_BLK_SZ;
  hashsize = c->size = SHA_HSH_SZ;
  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    ctxs ct;
    ret = lhsha_reset(&ct) || lhsha_input(&ct, key, key_len) ||
      lhsha_result(&ct, tmp);
    if (ret != SHA_OK) return ret;
    key = tmp;
    key_len = hashsize;
  }
  // HMAC Transform
  for (int i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36; c->k_opad[i] = key[i] ^ 0x5c;
  }
  // Remaining pad bytes are '\0' XOR'd with ipad and opad values
  for (int i = key_len; i < blocksize; i++) {
    k_ipad[i] = 0x36; c->k_opad[i] = 0x5c;
  }
  return c->corrupt = lhsha_reset(&c->sha) ||
    lhsha_input(&c->sha, k_ipad, blocksize);
}

//
// HMAC input
int lhhmac_input(ctxh *c, cuc *text, int text_len) {
  lhhmac_error(c); return c->corrupt = lhsha_input(&c->sha, text, text_len);
}

//
// HMAC Add final bits
int lhhmac_final(ctxh *c, uint8_t bits, uint32_t bit_count) {
  lhhmac_error(c); return c->corrupt = lhsha_final(&c->sha, bits, bit_count);
}

//
// HMAC Get digest
int lhhmac_result(ctxh *c, uint8_t *digest) {
  // Finish up 1st pass. Perform outer SHA, init context for 2nd pass.
  // Start with outer pad, then results of 1st hash. Finish up 2nd pass
  lhhmac_error(c);
  int ret = lhsha_result(&c->sha, digest) || lhsha_reset(&c->sha) ||
    lhsha_input(&c->sha, c->k_opad, c->blk_size) ||
    lhsha_input(&c->sha, digest, c->size) || lhsha_result(&c->sha, digest);
  c->compute = 1;
  return c->corrupt = ret;
}

//
// HMAC & SHA Test suite runner
int lh(cc *ta, int l,u64 r, int n, int eb, cuc *k, int kl, cc *ra,int hs) {
  uint8_t msg_dig[SHA_HSH_SZ], err;
  ctxh hmac; ctxs sha;

  if (k) {
    err = lhhmac_reset(&hmac, k, kl); if (err != SHA_OK) {return err;}
    for (u64 i = 0; i < r; ++i) {err = lhhmac_input(&hmac, (cuc *)ta, l);
      if (err != SHA_OK) {return err;}}
    if (n > 0) {err = lhhmac_final(&hmac, (uint8_t)eb, n);
      if (err != SHA_OK) {return err;}}
    err = lhhmac_result(&hmac, msg_dig); if (err != SHA_OK) {return err;}
  } else {
    err = lhsha_reset(&sha); if (err != SHA_OK) {return err;}
    for (u64 i = 0; i < r; ++i) {err = lhsha_input(&sha, (cuc *)ta, l);
      if (err != SHA_OK) {return err;}}
    if (n > 0) {err = lhsha_final(&sha, (uint8_t)eb, n);
      if (err != SHA_OK) {return err;}}
    err = lhsha_result(&sha, msg_dig); if (err != SHA_OK) {return err;}
  }
  return lhsha_match_to_str(msg_dig, ra, hs, NULL);
}

//
// Circular shift
static u64 ROL64(u64 a, u64 n) {
  if (MOD(n, 64) != 0) return (a << (MOD(n, 64))) ^ (a >> (64 - (MOD(n, 64))));
  return a;
}

//
// Convert a hex bitstring to a string
static void lh3bit2str(uint8_t *ss, char *s) {
  for (u64 i = 0; i < SHA3_BITS / 16; i++) {sprintf(&s[i * 2], "%.2x", ss[i]);}
}

//
// The state for the KECCAK-p[b, nr] permutation is comprised of b bits.
// The specifications in this Standard contain two other quantities related to
// b: b/25 and log2(b/25), denoted by w and l, respectively.
// The seven possible values for these variables that are defined for the KECCAK-p
// permutations are given in the columns of Table 1 below.
// b 25 50 100 200 400 800 1600
// w  1  2   4   8  16  32   64
// l  0  1   2   3   4   5    6
// Let S denote a string of b bits that represents the state for the KECCAK-p[b, nr] permutation.
// The corresponding state array, denoted by A, is defined as follows:
// For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, A[x, y, z]=S[w(5y+x)+z].
// For example, if b=1600, so that w=64,
static void lh3str2state(const uint8_t *s, u64 (*a)[5][5]) {
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {
      u64 lane = 0;
      for (int z = 0; z < 8; z++)
        lane = lane + ROL64(s[8 * (5 * y + x) + z], z * 8);
      (*a)[x][y] = lane;
    }
}

//
// Let A denote a state array. The corresponding string representation, denoted by S,
// can be constructed from the lanes and planes of A, as follows:
// For each pair of integers (i, j) such that 0≤i<5 and 0≤j<5, define the string Lane(i, j)
// by Lane(i,j)= A[i,j,0] || A[i,j,1] || A[i,j,2] || ... || A[i,j,w-2] || A[i,j,w-1].
static void lh3state2str(u64 (*a)[5][5], uint8_t *s) {
  int count = 0;

  for (int y = 0; y < 5; y++)
    for (int x = 0; x < 5; x++)
      for (int z = 0; z < 8; z++)
        s[count++] = (uint8_t)(ROL64((*a)[x][y], 64 - z * 8) & (u64)255);
}

//
// 1. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
// C[x, z] = A[x, 0, z] ⊕ A[x, 1, z] ⊕ A[x, 2, z] ⊕ A[x, 3, z] ⊕ A[x, 4, z].
// 2. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
// D[x, z] = C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z – 1) mod w].
// 3. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z] = A[x, y, z] ⊕ D[x, z].
static void lh3theta(u64 (*a)[5][5]) {
  u64 c[5], d[5] = {0};

  for (int x = 0; x < 5; x++)
    c[x] = ((*a)[x][0] ^ (*a)[x][1] ^ (*a)[x][2] ^ (*a)[x][3] ^ (*a)[x][4]);
  for (int x = 0; x < 5; x++)
    for (int z = 0; z < 64; z++) {
      u64 r1 = ROL64(c[MOD(x - 1, 5)], 64 - z);
      u64 r2 = ROL64(c[MOD(x + 1, 5)], 64 - MOD(z - 1, 64));
      d[x] = d[x] + ROL64((r1 ^ r2) & 1, z);
    }
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {(*a)[x][y] ^= d[x];}
}

//
// Steps:
// 1. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A[0, 0, z].
// 2. Let (x, y) = (1, 0).
// 3. For t from 0 to 23:
// a. for all z such that 0 ≤ z < w, let A′[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod w];
// b. let (x, y) = (y, (2x + 3y) mod 5).
// 4. Return A′.
static void lh3rho(u64 (*a)[5][5]) {
  u64 x = 1, y = 0, xtmp = 0, ap[5][5], cb;

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int t = 0; t < 24; t++) {
    (*a)[x][y] = 0;
    for (int z = 0; z < 64; z++) {
      cb = (ROL64(ap[x][y], 64 - MOD((z - (t + 1) * (t + 2) / 2), 64)) & 1);
      cb = ROL64(cb, z);
      (*a)[x][y] += cb;
    }
    xtmp = x;
    x = y;
    y = MOD((2 * xtmp + 3 * y), 5);
  }
}

//
// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z]= A[(x + 3y) mod 5, x, z].
// 2. Return A′.
static void lh3pi(u64 (*a)[5][5]) {
  u64 ap[5][5];

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {(*a)[x][y] = ap[MOD((x + 3 * y), 5)][x];}
}

//
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
static void lh3chi(u64 (*a)[5][5]) {
  u64 ap[5][5], one = 1, t1, t2, t3;

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {
      (*a)[x][y] = 0;
      for (int z = 0; z < 64; z++) {
        t1 = ap[x][y] & ROL64(one, z);
        t2 = (ap[MOD(x + 1, 5)][y] & ROL64(one, z)) ^ ROL64(one, z);
        t3 = ap[MOD(x + 2, 5)][y] & ROL64(one, z);
        (*a)[x][y] += t1 ^ (t2 & t3);
      }
    }
}

//
// Steps:
// 1. If t mod 255 = 0, return 1.
// 2. Let R = 10000000.
// 3. For i from 1 to t mod 255, let:
//   a. R=0||R;
//   b. R[0] = R[0] ⊕ R[8];
//   c. R[4] = R[4] ⊕ R[8];
//   d. R[5] = R[5] ⊕ R[8];
//   e. R[6] = R[6] ⊕ R[8];
//   f. R =Trunc8[R].
// 4. Return R[0]
static uint8_t lh3rc(u64 t) {
  uint8_t m = MOD(t, 255), r1 = 128, r0;

  if (m == 0) return 1;
  for (u64 i = 1; i <= m; i++) {
    r0 = 0;
    r0 ^= MOD(r1, 2);
    for (int j = 4; j >= 2; j--) {r1 ^= MOD(r1, 2) << j;}
    r1 /= 2;
    r1 ^= r0 << 7;
  }
  return r1 >> 7;
}

//
// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and
//      0 ≤ z < w, let A′[x, y, z] = A[x, y, z].
// 2. Let RC = 0w.
// 3. For j from 0 to l, let RC[2j – 1] = rc(j + 7ir).
// 4. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ⊕ RC[z].
// 5. Return A′.
static void lh3iota(u64 (*A)[5][5], u64 ir) {
  u64 r = 0;

  for (u64 i = 0; i <= 6; i++) {r += ROL64(lh3rc(i+7*ir),(int)pow(2,i)-1);}
  (*A)[0][0] ^= r;
}

//
// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
static void lh3keccak_p(uint8_t *sm, uint8_t s[200]) {
  u64 a[5][5];

  lh3str2state(sm, &a);
  // Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir). // nr = 24; ir = 24 - nr; ir <= 23;
  for (int i = 0; i <= 23; i++) {
    lh3theta(&a);lh3rho(&a);lh3pi(&a);lh3chi(&a);lh3iota(&a,i);
  }
  lh3state2str(&a, s);
}


//
// Concatenate
static u64 lh3cat(uint8_t *x, u64 xl, uint8_t *y, u64 yl, uint8_t **z) {
  u64 zbil = xl + yl, xl8 = xl / 8, mxl8 = MOD(xl, 8);

  *z = calloc(512, sizeof(uint8_t));
  if (*z == NULL) return 0;
  memcpy(*z, x, xl8);
  for (u64 i = 0; i < mxl8; i++) {(*z)[xl8] |= (x[xl8] & (1 << i));}
  u64 zbyc = xl8, zbic = mxl8, ybyc = 0, ybic = 0, v;
  for (u64 i = 0; i < yl; i++) {
    v = ((y[ybyc] >> ybic) & 1);
    (*z)[zbyc] |= (v << zbic);
    if (++ybic == 8) {ybyc++; ybic = 0;}
    if (++zbic == 8) {zbyc++; zbic = 0;}
  }
  return zbil;
}

//
// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
static u64 lh3pad10(u64 x, u64 m, uint8_t **p) {
  long j = MOD((-m - 2), x) + 2;
  int bl = (j) / 8 + (MOD(j, 8) ? 1 : 0);

  *p = calloc(bl, sizeof(uint8_t));
  (*p)[0] |= 1;
  (*p)[bl - 1] |= (1 << MOD(j - 1, 8));
  return j;
}

//
// Steps:
// 1. Let P=N || pad(r, len(N)).
// 2. Let n = len(P)/r.
// 3. Let c=b-r.
// 4. Let P0, ... , Pn-1 be the unique sequence of strings of length r such
//      that P = P0 || ... || Pn-1.
// 5. Let S=0b.
// 6. For i from 0 to n-1, let S=f(S ⊕ (Pi || 0c)).
// 7. Let Z be the empty string.
// 8. Let Z=Z || Truncr(S).
// 9. If d ≤ |Z|, then return Trunc d (Z); else continue.
// 10. Let S=f(S), and continue with Step 8.
static void lh3sponge(uint8_t *n, int l, uint8_t **ps) {
  u64 b = 1600, c = 512, len, plen, zl = 0, r = b - SHA3_BITS;
  uint8_t az[64] = {0}, s[200] = {0}, sc[200] = {0}, sxor[200] = {0}, *p, *pi, *z=NULL, *pad, str[200] = {0};

  len = lh3pad10(r, l, &pad);
  plen = lh3cat(n, l, pad, len, &p);
  for (u64 i = 0; i < plen / r; i++) {
    lh3cat(&p[i * r / 8], r, az, c, &pi);
    for (u64 j = 0; j < b / 8; j++) {sxor[j] = s[j] ^ pi[j];}
    free(pi);
    lh3keccak_p(sxor, s);
  }
  while (true) {
    memcpy(str, s, r / 8);
    zl = lh3cat(z, zl, str, r, &z);
    if (zl >= SHA3_BITS) {memcpy((*ps), z, 512 / 8); break;}
    memcpy(sc, s, b / 8);
    lh3keccak_p(sc, s);
  }
  free(pad); free(p); free(z);
}

//
// Specification of KECCAK[c]
// KECCAK is the family of sponge functions with the KECCAK-p[b, 12 + 2l]
// permutation (defined in Sec 3.3) as the underlying function and with pad10*1
// (defined in Sec. 5.1) as the padding rule. The family is parameterized by
// any choices of the rate r and the capacity c such that r + c is in
// {25, 50, 100, 200, 400, 800, 1600}, i.e., one of the seven values for b in
// Table 1.

// When restricted to the case b = 1600, the KECCAK family is denoted by
// KECCAK[c]; in this case r is determined by the choice of c.

// In particular,
// KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600 – c].

// Thus, given an input bit string N and an output length d,
// KECCAK[c] (N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600 – c] (N, d).
void lh3new(uint8_t *n, char *s) {
  uint8_t *m = malloc(256 * sizeof(uint8_t)), z1[] = {2}, *ss = malloc(256 * sizeof(uint8_t));
  u64 d = strlen((char*)n) * 8;

  lh3cat(n, d, z1, 2, &m);
  lh3sponge(m, d + 2, &ss);
  lh3bit2str(ss, s);
  for (int i = 0; i < 128; i++) printf("%d %01x : %d %c :: %d %01x ::: %llu\n", ss[i], ss[i], s[i], s[i], m[i], m[i], (d+2));
  free(m);free(ss);
}

// Shake inspired from https://github.com/mjosaarinen/tiny_sha3
void lh3shake_xof(uint8_t *sm, uint8_t (*s)[200]) {
  sm[64] ^= 0x1F;
  sm[135] ^= 0x80;
  lh3keccak_p(sm, sm);
}

uint8_t lh3shake_touch(uint8_t *sm, uint8_t s[200], uint8_t next, bool upd) {
  uint8_t j = next;

  if (upd) {
    for (size_t i = 0; i < 20; i++) {
      sm[j++] ^= 163;//sm[i];
      if (j >= 136) {
        lh3keccak_p(sm, sm); j = 0;
      }
    }
  } else {
    for (size_t i = 0; i < 32; i++) {
      if (j >= 136) {
        lh3keccak_p(sm, sm); j = 0;
      }
      s[i] = sm[j++];
    }
  }
  return j;
}

void lh3shake_test() {
  uint8_t *buf = malloc(200*sizeof(uint8_t)), *str = malloc(200*sizeof(uint8_t)), next = 0, next2 = 0, s[200] = {0};
  char sss[64], ss[] = "6a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb";

  memset(buf, 0xA3, 20);
  for (int j = 0; j < 200; j += 20) {next = lh3shake_touch(str, buf, next, true);}
  lh3shake_xof(str, &s);
  for (int i = 0; i < 32; i++) s[i] = str[i];
  for (int j = 0; j < 512; j += 32) {next2 = lh3shake_touch(str, s, next2, false);}
  lh3bit2str(s, sss);
  for (int i = 0; i < 64; i++) {assert(sss[i] == ss[i]);}
  if (*ss) {}
  // verified assert via debug mode
  free(buf); free(str);
}
