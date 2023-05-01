// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "lighthash.h"
#include "lightdefs.h"
#include "lighttools.h"

//
// Circular shift
static u64 shift_cir(u64 a, u64 n) {
  u64 m = MOD(n, 64);

  if (m != 0)
    return a << m ^ a >> (64 - m);
  return a;
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
static void str2state(u64 (*a)[5][5], const uint8_t *s) {
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {
      u64 lane = 0;
      for (int z = 0; z < 8; z++)
        lane += shift_cir(s[8 * (5 * y + x) + z], z * 8);
      (*a)[x][y] = lane;
    }
}

//
// Let A denote a state array. The corresponding string representation, denoted by S,
// can be constructed from the lanes and planes of A, as follows:
// For each pair of integers (i, j) such that 0≤i<5 and 0≤j<5, define the string Lane(i, j)
// by Lane(i,j)= A[i,j,0] || A[i,j,1] || A[i,j,2] || ... || A[i,j,w-2] || A[i,j,w-1].
static void state2str(uint8_t *s, u64 (*a)[5][5]) {
  for (int count = 0, y = 0; y < 5; y++)
    for (int x = 0; x < 5; x++)
      for (int z = 0; z < 8; z++)
        s[count++] = (uint8_t)(shift_cir((*a)[x][y], 64 - z * 8) & (u64)255);
}

//
// 1. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
// C[x, z] = A[x, 0, z] ⊕ A[x, 1, z] ⊕ A[x, 2, z] ⊕ A[x, 3, z] ⊕ A[x, 4, z].
// 2. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
// D[x, z] = C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z – 1) mod w].
// 3. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z] = A[x, y, z] ⊕ D[x, z].
static void theta(u64 (*a)[5][5]) {
  u64 c[5], d[5] = {0};

  for (int x = 0; x < 5; x++)
    c[x] = ((*a)[x][0] ^ (*a)[x][1] ^ (*a)[x][2] ^ (*a)[x][3] ^ (*a)[x][4]);
  for (int x = 0; x < 5; x++)
    for (int z = 0; z < 64; z++) {
      u64 r1 = shift_cir(c[MOD(x - 1, 5)], 64 - z), r2 = shift_cir(c[MOD(x + 1, 5)], 64 - MOD(z - 1, 64));
      d[x] = d[x] + shift_cir((r1 ^ r2) & 1, z);
    }
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++)
      (*a)[x][y] ^= d[x];
}

//
// Steps:
// 1. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A[0, 0, z].
// 2. Let (x, y) = (1, 0).
// 3. For t from 0 to 23:
// a. for all z such that 0 ≤ z < w, let A′[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod w];
// b. let (x, y) = (y, (2x + 3y) mod 5).
// 4. Return A′.
static void rho(u64 (*a)[5][5]) {
  u64 x = 1, y = 0, xtmp = 0, ap[5][5], cb;

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int t = 0; t < 24; t++) {
    (*a)[x][y] = 0;
    for (int z = 0; z < 64; z++) {
      cb = (shift_cir(ap[x][y], 64 - MOD((z - (t + 1) * (t + 2) / 2), 64)) & 1);
      (*a)[x][y] += shift_cir(cb, z);
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
static void pi(u64 (*a)[5][5]) {
  u64 ap[5][5];

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++)
      (*a)[x][y] = ap[MOD((x + 3 * y), 5)][x];
}

//
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
static void chi(u64 (*a)[5][5]) {
  u64 ap[5][5], one = 1, t1, t2, t3;

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {
      (*a)[x][y] = 0;
      for (int z = 0; z < 64; z++) {
        t1 = ap[x][y] & shift_cir(one, z);
        t2 = (ap[MOD(x + 1, 5)][y] & shift_cir(one, z)) ^ shift_cir(one, z);
        t3 = ap[MOD(x + 2, 5)][y] & shift_cir(one, z);
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
static uint8_t rc(u64 t) {
  uint8_t m = MOD(t, 255), r1 = 128, r0;

  if (m == 0) return 1;
  for (u64 i = 1; i <= m; i++) {
    r0 = 0;
    r0 ^= MOD(r1, 2);
    for (int j = 4; j >= 2; j--)
      r1 ^= MOD(r1, 2) << j;
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
static void iota(u64 (*a)[5][5], const u64 ir) {
  u64 r = 0;

  for (u64 i = 0; i <= 6; i++)
    r += shift_cir(rc(i + 7 * ir), (int)pow(2, i) - 1);
  (*a)[0][0] ^= r;
}

//
// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
// Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir). // nr = 24; ir = 24 - nr; ir <= 23;
static void keccak_p(uint8_t s[], u64 (*ss)[5][5], const uint8_t *sm, bool str) {
  u64 a[5][5];

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
static u64 cat(uint8_t **z, const uint8_t *x, const u64 xl, const uint8_t *y, const u64 yl) {
  u64 zbil = xl + yl, xl8 = xl / 8, mxl8 = MOD(xl, 8);

  *z = calloc(512, sizeof(uint8_t));
  if (*z == NULL) return 0;
  memcpy(*z, x, xl8);
  for (u64 i = 0; i < mxl8; i++)
    (*z)[xl8] |= (x[xl8] & (1 << i));
  u64 zbyc = xl8, zbic = mxl8, ybyc = 0, ybic = 0;
  for (u64 i = 0; i < yl; i++) {
    (*z)[zbyc] |= (((y[ybyc] >> ybic) & 1) << zbic);
    if (++ybic == 8) {ybyc++; ybic = 0;}
    if (++zbic == 8) {zbyc++; zbic = 0;}
  }
  return zbil;
}

//
// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
static u64 pad10(uint8_t **p, const u64 x, const u64 m) {
  u64 j = MOD((-m - 2), x) + 2, bl = (j) / 8 + (MOD(j, 8) ? 1 : 0);

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
static void sponge(uint8_t **ps, const uint8_t *n, const int l) {
  uint8_t az[64] = {0}, s[200] = {0}, sc[200] = {0}, sxor[200] = {0}, *pad, str[200] = {0}, *p, *pi, *z = NULL;
  u64 b = 1600, c = 512, len, plen, zl = 0, r = b - SHA3_BITS;

  len = pad10(&pad, r, l);
  plen = cat(&p, n, l, pad, len);
  for (u64 i = 0; i < plen / r; i++) {
    cat(&pi, &p[i * r / 8], r, az, c);
    for (u64 j = 0; j < b / 8; j++)
      sxor[j] = s[j] ^ pi[j];
    free(pi);
    keccak_p(s, NULL, sxor, true);
  }
  while (true) {
    memcpy(str, s, r / 8);
    zl = cat(&z, z, zl, str, r);
    if (zl >= SHA3_BITS) {
      memcpy((*ps), z, 64); break;
    }
    memcpy(sc, s, b / 8);
    keccak_p(s, NULL, sc, true);
  }
  free(pad); free(p); free(z);
}

static void two2one(u64 ret[5][5], u64 a[25]) {
  for (int i = 0; i < 5; i++)
    for (int j = 0; j < 5; j++)
      ret[j][i] = a[j + 5 * i];
}

static void one2two(u64 ret[25], u64 a[5][5]) {
  for (int i = 0; i < 5; i++)
    for (int j = 0; j < 5; j++)
      ret[j + 5 * i] = a[j][i];
}

static u64 load64(const uint8_t x[8]) {
  u64 r = 0;

  for (uint32_t i = 0; i < 8; i++)
    r |= (u64)x[i] << 8 * i;
  return r;
}

static void store64(uint8_t x[8], u64 u) {
  for (uint32_t i = 0; i < 8; i++)
    x[i] = u >> 8 * i;
}

static void keccak_absorb(u64 s[25], uint32_t r, const uint8_t *m, uint32_t mlen, uint8_t p) {
  uint8_t t[200] = {0};
  u64 ss[5][5];

  memset(s, 0, 25 * sizeof(u64));
  while (mlen >= r) {
    two2one(ss, s);
    for (uint32_t i = 0; i < r / 8; i++)
      s[i] ^= load64(m + 8 * i);
    keccak_p(NULL, &ss, NULL, false);
    mlen -= r;
    m += r;
    one2two(s, ss);
  }
  memcpy(t, m, sizeof(uint8_t) * mlen);
  t[mlen] = p;
  t[r - 1] |= 128;
  for (uint32_t i = 0; i < r / 8; i++)
    s[i] ^= load64(t + 8 * i);
}

static void keccak_squeezeblocks(uint8_t *out, uint32_t nblocks, u64 s[25], uint32_t r) {
  u64 ss[5][5];

  two2one(ss, s);
  while (nblocks > 0) {
    keccak_p(NULL, &ss, NULL, false);
    one2two(s, ss);
    for (uint32_t i = 0; i < r / 8; i++)
      store64(out + 8 * i, s[i]);
    out += r;
    --nblocks;
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
  u64 d = strlen((char*)n) * 8, l = 256 * sizeof(uint8_t);
  uint8_t *ss = malloc(l), z1[] = {2}, *mmm;

  cat(&mmm, n, d, z1, 2);
  sponge(&ss, mmm, d + 2);
  bit_hex_str(s, ss, 64);
  free(ss); free(mmm);
}

void hash_shake_new(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen) {
  uint32_t nblocks = outlen / 136;
  uint8_t t[inlen];
  u64 st[25];

  keccak_absorb(st, 136, in, inlen, 0x1F);
  keccak_squeezeblocks(out, nblocks, st, 136);

  out += nblocks * 136;
  outlen -= nblocks * 136;

  if (outlen) {
    keccak_squeezeblocks(t, 1, st, 136);
    for (uint32_t i = 0; i < outlen; i++)
      out[i] = t[i];
  }
}

// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
// https://hashes.com/en/generate/hash
