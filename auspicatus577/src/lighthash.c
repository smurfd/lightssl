// Auth: smurfd, 2023 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "lighthash.h"

// TODO: SLOOOOOOoooooOOO0000WW!
// TODO: FIX: rewrite to use uint8_t instead of u64 when xor:ing, extremely slow to xor u64 and u64

//
// 0-255 to 0x0 to 0xff
static inline void to_hex_chr(char *hs, uint8_t *h) {
  static char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  hs[0] = hex[h[0]];
  hs[1] = hex[h[1]];
}

//
// Convert a hex bitstring to a string
static inline void bit_hex_str(char *hs, const uint8_t *d, const int len) {
  uint8_t h[2] = {0}, hc[2] = {0};
  hs[0] = '0';
  hs[1] = 'x';
  for (int co=2, i = 0; i < len; i++) {
    h[0] = d[i] >> 4;
    h[1] = d[i] & 0xf;
    to_hex_chr((char*)hc, h);
    hs[co++] = (char)hc[0];
    hs[co++] = (char)hc[1];
  }
}

//
// Circular shift
static inline u64 shift_cir16(u64 a, uint8_t n) {
  uint8_t m = MOD(n, 64);
  return (a = (m != 0) ? (a << m ^ a >> (64 - m)) : a);
}

static inline u64 shift_cir8(uint8_t a, uint8_t n) {
  u64 ret = a;
  uint8_t m = MOD(n, 64);
  return (ret = (m != 0) ? ((u64)a << m ^ (u64)a >> (64 - m)) : ret);
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
static inline void str2state(u64 (*a)[5][5], const uint8_t *s) {
  for (uint8_t x = 0; x < 5; x++) {
    for (uint8_t y = 0; y < 5; y++) {
      u64 lane = 0;
      for (uint8_t z = 0; z < 8; z++) {
        lane += shift_cir16(s[8 * (5 * y + x) + z], z * 8);
      }
      (*a)[x][y] = lane;
    }
  }
}

//
// Let A denote a state array. The corresponding string representation, denoted by S,
// can be constructed from the lanes and planes of A, as follows:
// For each pair of integers (i, j) such that 0≤i<5 and 0≤j<5, define the string Lane(i, j)
// by Lane(i,j)= A[i,j,0] || A[i,j,1] || A[i,j,2] || ... || A[i,j,w-2] || A[i,j,w-1].
static inline void state2str(uint8_t *s, u64 (*a)[5][5]) {
  for (uint8_t count = 0, y = 0; y < 5; y++) {
    for (uint8_t x = 0; x < 5; x++) {
      for (uint8_t z = 0; z < 8; z++) {
        s[count++] = (shift_cir16((*a)[x][y], 64 - z * 8) & (u64)255);
      }
    }
  }
}

//
// 1. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
// C[x, z] = A[x, 0, z] ⊕ A[x, 1, z] ⊕ A[x, 2, z] ⊕ A[x, 3, z] ⊕ A[x, 4, z].
// 2. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
// D[x, z] = C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z – 1) mod w].
// 3. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z] = A[x, y, z] ⊕ D[x, z].
static inline void theta(u64 (*a)[5][5]) {
  u64 c[5] = {0}, d[5] = {0};
  for (uint8_t x = 0; x < 5; x++) {
    c[x] = ((*a)[x][0] ^ (*a)[x][1] ^ (*a)[x][2] ^ (*a)[x][3] ^ (*a)[x][4]);
  }
  for (uint8_t x = 0; x < 5; x++) {
    uint8_t mx1 = MOD(x - 1, 5), mx2 = MOD(x + 1, 5);
    for (uint8_t z = 0; z < 64; z++) {
      uint8_t r1 = shift_cir16(c[mx1], 64 - z), r2 = shift_cir16(c[mx2], 64 - MOD(z - 1, 64));
      d[x] = d[x] + shift_cir8((r1 ^ r2) & 1, z);
    }
  }
  for (uint8_t x = 0; x < 5; x++) {
    (*a)[x][0] ^= d[x]; (*a)[x][1] ^= d[x]; (*a)[x][2] ^= d[x]; (*a)[x][3] ^= d[x]; (*a)[x][4] ^= d[x];
  }
}

//
// Steps:
// 1. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A[0, 0, z].
// 2. Let (x, y) = (1, 0).
// 3. For t from 0 to 23:
// a. for all z such that 0 ≤ z < w, let A′[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod w];
// b. let (x, y) = (y, (2x + 3y) mod 5).
// 4. Return A′.
static inline void rho(u64 (*a)[5][5]) {
  uint8_t x = 1, y = 0, xtmp = 0, cb;
  u64 ap[5][5];
  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (uint8_t t = 0; t < 24; t++) {
    uint8_t tt = (t + 1) * (t + 2) >> 1;/// 2;
    (*a)[x][y] = 0;
    for (uint8_t z = 0; z < 64; z++) {
      cb = (shift_cir16(ap[x][y], 64 - MOD((z - tt), 64)) & 1);
      (*a)[x][y] += shift_cir8(cb, z);;
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
static inline void pi(u64 (*a)[5][5]) {
  u64 ap[5][5] = {0};
  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (uint8_t x = 0; x < 5; x++) {
    for (uint8_t y = 0; y < 5; y++) {
      (*a)[x][y] = ap[MOD((x + 3 * y), 5)][x];
    }
  }
}

//
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
static inline void chi(u64 (*a)[5][5]) {
  u64 ap[5][5] = {0}, one = 1, t1, t2, t3, t4;
  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (uint8_t x = 0; x < 5; x++) {
    uint8_t mx1 = MOD(x + 1, 5), mx2 = MOD(x + 2, 5);
    for (uint8_t y = 0; y < 5; y++) {
      (*a)[x][y] = 0;
      for (uint8_t z = 0; z < 64; z++) {
        u64 sc = shift_cir8(one, z);
        t1 = ap[x][y] & sc;
        t2 = (ap[mx1][y] & sc) ^ sc;
        t3 = ap[mx2][y] & sc;
        t4 = t1 ^ (t2 & t3);
        (*a)[x][y] += t4;
      }
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
/*
// Not used, precalculated
static inline uint8_t rc(u64 t) {
  uint8_t m = MOD(t, 255), r1 = 128, r0;
  if (m == 0) return 1;
  for (u64 i = 1; i <= m; i++) {
    r0 = 0;
    r0 ^= MOD(r1, 2);
    for (int j = 4; j >= 2; j--) {
      r1 ^= MOD(r1, 2) << j;
    }
    r1 = r1 >> 1; // / 2
    r1 ^= r0 << 7;
  }
  return r1 >> 7;
}
*/

//
// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and
//      0 ≤ z < w, let A′[x, y, z] = A[x, y, z].
// 2. Let RC = 0w.
// 3. For j from 0 to l, let RC[2j – 1] = rc(j + 7ir).
// 4. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ⊕ RC[z].
// 5. Return A′.
static inline void iota(u64 (*a)[5][5], const uint8_t ir) {
  uint8_t pw[7] = {0, 1, 3, 7, 15, 31, 63};
  u64 r = 0;
  for (uint8_t i = 0; i <= 6; i++) {
    r += shift_cir16(rc_precalc[ir][i], pw[i]);
  }
  (*a)[0][0] ^= r;
}

//
// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
// Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir). // nr = 24; ir = 24 - nr; ir <= 23;
static inline void keccak_p(uint8_t *s, u64 (*ss)[5][5], const uint8_t *sm, bool str) {
  u64 a[5][5] = {0};
  if (str) str2state(&a, sm);
  else memcpy(&a, (*ss), 25 * sizeof(u64));
  for (int i = 0; i <= 23; i++) {
    theta(&a); rho(&a); pi(&a); chi(&a); iota(&a, i);
  }
  if (str) state2str(s, &a);
  else memcpy((*ss), &a, 25 * sizeof(u64));
}

//
// Concatenate
static inline uint16_t cat(uint8_t *z, const uint8_t *x, const uint16_t xl, const uint8_t *y, const uint16_t yl) {
  uint16_t zbil = xl + yl, xl8 = DIV8(xl), mxl8 = MOD(xl, 8), zbyc = xl8, zbic = mxl8, ybyc = 0, ybic = 0;
  memcpy(z, x, xl8);
  for (uint16_t i = 0; i < mxl8; i++) {
    z[xl8] |= (x[xl8] & (1 << i));
  }
  for (uint16_t i = 0; i < yl; i++) {
    z[zbyc] |= (((y[ybyc] >> ybic) & 1) << zbic);
    if (++ybic == 8) {ybyc++; ybic = 0;}
    if (++zbic == 8) {zbyc++; zbic = 0;}
  }
  return zbil;
}

//
// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
static inline uint16_t pad10(uint8_t *p, const uint16_t x, const uint16_t m) {
  uint16_t j = MOD((-m - 2), x) + 2, bl = (DIV8(j)) + (MOD(j, 8) ? 1 : 0);
  memset(p, 0, bl * sizeof(uint8_t));
  p[0] |= 1;
  p[bl - 1] |= (1 << MOD(j - 1, 8));
  return j;
}

static inline void keccak_p1(uint8_t *s, const uint8_t *sm) { // str true
  u64 a[5][5] = {0};
  str2state(&a, sm);
  for (int i = 0; i <= 23; i++) {
    theta(&a); rho(&a); pi(&a); chi(&a); iota(&a, i);
  }
  state2str(s, &a);
}

static inline void keccak_p2(u64 (*ss)[5][5]) { // str false
  u64 a[5][5] = {0};
  memcpy(&a, (*ss), 25 * sizeof(u64));
  for (int i = 0; i <= 23; i++) {
    theta(&a); rho(&a); pi(&a); chi(&a); iota(&a, i);
  }
  memcpy((*ss), &a, 25 * sizeof(u64));
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
static inline void sponge(uint8_t *ps, const uint8_t *n, const int l) {
  uint8_t az[64] = {0}, s[200] = {0}, sc[200] = {0}, sxor[200] = {0}, str[200] = {0};
  uint8_t pad[1600] = {0}, p[1600] = {0}, pi[1600] = {0}, z[1600] = {0};
  uint16_t b = 1600, c = 512, zl = 0, r = b - SHA3_BITS, len = pad10(pad, r, l), plen = cat(p, n, l, pad, len); // between 500 & 1000+
  for (uint16_t i = 0; i < plen / r; i++) {
    cat(pi, &p[i * DIV8(r)], r, az, c);
    for (uint16_t j = 0; j < DIV8(b); j++) {
      sxor[j] = s[j] ^ pi[j];
    }
    keccak_p1(s, sxor);
  }
  while (true) {
    memcpy(str, s, DIV8(r));
    zl = cat(z, z, zl, str, r);
    if (zl >= SHA3_BITS) {
      memcpy(ps, z, 64); break;
    }
    memcpy(sc, s, DIV8(b));
    keccak_p1(s, sc);
  }
}

static inline void two2one(u64 ret[5][5], u64 a[25]) {
  for (uint8_t i = 0; i < 5; i++) {
    ret[0][i] = a[(5 * i) + 0];
    ret[1][i] = a[(5 * i) + 1];
    ret[2][i] = a[(5 * i) + 2];
    ret[3][i] = a[(5 * i) + 3];
    ret[4][i] = a[(5 * i) + 4];
  }
}

static inline void one2two(u64 ret[25], u64 a[5][5]) {
  for (uint8_t i = 0; i < 5; i++) {
    ret[(5 * i) + 0] = a[0][i];
    ret[(5 * i) + 1] = a[1][i];
    ret[(5 * i) + 2] = a[2][i];
    ret[(5 * i) + 3] = a[3][i];
    ret[(5 * i) + 4] = a[4][i];
  }
}

static inline u64 load64(const uint8_t x[8]) {
  u64 r = 0;
  for (uint8_t i = 0; i < 8; i++) {
    r |= (u64)x[i] << 8 * i;
  }
  return r;
}

static inline void store64(uint8_t x[8], u64 u) {
  for (uint8_t i = 0; i < 8; i++) {
    x[i] = u >> 8 * i;
  }
}

static inline void keccak_absorb(u64 s[25], uint32_t r, const uint8_t *m, uint32_t mlen, uint8_t p) {
  uint8_t t[200] = {0};
  u64 ss[5][5] = {0};
  memset(s, 0, 25 * sizeof(u64));
  while (mlen >= r) {
    two2one(ss, s);
    for (uint32_t i = 0; i < DIV8(r); i++) {
      s[i] ^= load64(m + 8 * i);
    }
    keccak_p2(&ss);
    mlen -= r;
    m += r;
    one2two(s, ss);
  }
  memcpy(t, m, sizeof(uint8_t) * mlen);
  t[mlen] = p;
  t[r - 1] |= 128;
  for (uint32_t i = 0; i < DIV8(r); i++) {
    s[i] ^= load64(t + 8 * i);
  }
}

static inline void keccak_squeezeblocks(uint8_t *out, uint32_t nblocks, u64 s[25], uint32_t r) {
  u64 ss[5][5] = {0};
  two2one(ss, s);
  while (nblocks > 0) {
    keccak_p2(&ss);
    one2two(s, ss);
    for (uint32_t i = 0; i < DIV8(r); i++) {
      store64(out + 8 * i, s[i]);
    }
    out += r;
    nblocks--;
  }
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
void hash_new(char *s, const uint8_t *n) {
  uint8_t z1[] = {2}, mmm[512] = {0}, ss[512] = {0};
  u64 d = strlen((char*)n) * 8;
  cat(mmm, n, d, z1, 2);
  sponge(ss, mmm, d + 2);
  bit_hex_str(s, ss, 64);
}

void hash_shake_new(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen) {
  u64 nblocks = outlen / 136, st[25] = {0};
  uint8_t t[512] = {0};
  keccak_absorb(st, 136, in, inlen, 0x1F);
  keccak_squeezeblocks((uint8_t*)out, nblocks, st, 136);
  out += nblocks * 136;
  outlen -= nblocks * 136;
  if (outlen) {
    keccak_squeezeblocks(t, 1, st, 136);
    memcpy(out, t, outlen * sizeof(uint8_t));
  }
}
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
// https://hashes.com/en/generate/hash
