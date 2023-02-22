// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lighthash3.h"
#include "lightdefs.h"

//
// Circular shift
static uint64_t ROL64(uint64_t a, uint64_t n) {
  if (MOD(n, 64) != 0) return (a << (MOD(n, 64))) ^ (a >> (64 - (MOD(n, 64))));
  return a;
}

//
// Convert a hex bitstring to a string
static void bit2str(uint8_t *ss, char *s) {
  for (uint64_t i = 0; i < SHA3_BITS / 16; i++) {sprintf(&s[i * 2], "%.2x", ss[i]);}
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
static void str2state(const uint8_t *s, uint64_t (*a)[5][5]) {
  uint64_t lane;

  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      lane = 0;
      for (int z = 0; z < 8; z++) {
        lane = lane + ROL64(s[8 * (5 * y + x) + z], z * 8);
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
static void state2str(uint64_t (*a)[5][5], uint8_t *s) {
  int count = 0;

  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      for (int z = 0; z < 8; z++) {
        s[count++] = (uint8_t)(ROL64((*a)[x][y], 64 - z * 8) & (uint64_t)255);
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
static void theta(uint64_t (*a)[5][5]) {
  uint64_t c[5], d[5] = {0};

  for (int x = 0; x < 5; x++) {
    c[x] = ((*a)[x][0] ^ (*a)[x][1] ^ (*a)[x][2] ^ (*a)[x][3] ^ (*a)[x][4]);
  }
  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < 64; z++) {
      uint64_t r1 = ROL64(c[MOD(x - 1, 5)], 64 - z);
      uint64_t r2 = ROL64(c[MOD(x + 1, 5)], 64 - MOD(z - 1, 64));
      d[x] = d[x] + ROL64((r1 ^ r2) & 1, z);
    }
  }
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {(*a)[x][y] ^= d[x];}
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
static void rho(uint64_t (*a)[5][5]) {
  uint64_t x = 1, y = 0, xtmp = 0, ap[5][5], cb;

  memcpy(ap, *a, sizeof(uint64_t) * 5 * 5);
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
static void pi(uint64_t (*a)[5][5]) {
  uint64_t ap[5][5];

  memcpy(ap, *a, sizeof(uint64_t) * 5 * 5);
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {(*a)[x][y] = ap[MOD((x + 3 * y), 5)][x];}
  }
}

//
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
static void chi(uint64_t (*a)[5][5]) {
  uint64_t ap[5][5], one = 1, t1, t2, t3;

  memcpy(ap, *a, sizeof(uint64_t) * 5 * 5);
  for (int x = 0; x < 5; x++) {
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
static uint8_t rc(uint64_t t) {
  uint8_t m = MOD(t, 255), r1 = 128, r0;

  if (m == 0) return 1;
  for (uint64_t i = 1; i <= m; i++) {
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
static void iota(uint64_t (*A)[5][5], uint64_t ir) {
  uint64_t r = 0;

  for (uint64_t i = 0; i <= 6; i++) {r += ROL64(rc(i + 7 * ir), (int)pow(2, i) - 1);}
  (*A)[0][0] ^= r;
}

//
// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
static void keccak_p(uint8_t *sm, uint8_t (*s)[200]) {
  uint64_t a[5][5];

  str2state(sm, &a);
  // Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir). // nr = 24; ir = 24 - nr; ir <= 23;
  for (int i = 0; i <= 23; i++) {theta(&a);rho(&a);pi(&a);chi(&a);iota(&a,i);}
  state2str(&a, (*s));
}

//
// Concatenate
static uint64_t cat(const uint8_t *x, uint64_t xl, const uint8_t *y,
  const uint64_t yl, uint8_t **z) {
  uint64_t zbil = xl + yl, xl8 = xl / 8, mxl8 = MOD(xl, 8);

  *z = calloc(512, sizeof(uint8_t));
  if (*z == NULL) return 0;
  memcpy(*z, x, xl8);
  for (uint64_t i = 0; i < mxl8; i++) {(*z)[xl8] |= (x[xl8] & (1 << i));}
  uint64_t zbyc = xl8, zbic = mxl8, ybyc = 0, ybic = 0, v;
  for (uint64_t i = 0; i < yl; i++) {
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
static uint64_t pad10(uint64_t x, uint64_t m, uint8_t **p) {
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
static void sponge(uint8_t *n, int l, uint8_t **ps) {
  uint64_t b = 1600, c = 512, len, plen, zl = 0, r = b - SHA3_BITS;
  uint8_t az[64] = {0}, s[200] = {0}, sc[200] = {0}, sxor[200] = {0};
  uint8_t *p, *pi, *z, *pad, str[200] = {0};

  len = pad10(r, l, &pad);
  plen = cat(n, l, pad, len, &p);
  for (uint64_t i = 0; i < plen / r; i++) {
    cat(&p[i * r / 8], r, az, c, &pi);
    for (uint64_t j = 0; j < b / 8; j++) {sxor[j] = s[j] ^ pi[j];}
    free(pi);
    keccak_p(sxor, &s);
  }

  while (true) {
    memcpy(str, s, r / 8);
    zl = cat(z, zl, str, r, &z);
    if (zl >= SHA3_BITS) {memcpy((*ps), z, 512 / 8); break;}
    memcpy(sc, s, b / 8);
    keccak_p(sc, &s);
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
void lhash3_hash_new(uint8_t *n, char *s) {
  uint8_t *m, z1[] = {2}, *ss = malloc(128 * sizeof(uint8_t));
  uint64_t d = strlen((char*)n) * 8;

  cat(n, d, z1, 2, &m);
  sponge(m, d + 2, &ss);
  bit2str(ss, s);
  free(ss);
}
