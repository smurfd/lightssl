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
static u64 ROL64(u64 a, u64 n) {
  if (MOD(n, 64) != 0) return (a << (MOD(n, 64))) ^ (a >> (64 - (MOD(n, 64))));
  return a;
}

//
// Convert a hex bitstring to a string
static void bit2str(u08 *ss, char *s) {
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
static void str2state(const u08 *s, u64 (*a)[5][5]) {
  u64 lane;

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
static void state2str(u64 (*a)[5][5], u08 *s) {
  int count = 0;

  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      for (int z = 0; z < 8; z++) {
        s[count++] = (u08)(ROL64((*a)[x][y], 64 - z * 8) & (u64)255);
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
static void theta(u64 (*a)[5][5]) {
  u64 c[5], d[5] = {0};

  for (int x = 0; x < 5; x++) {
    c[x] = ((*a)[x][0] ^ (*a)[x][1] ^ (*a)[x][2] ^ (*a)[x][3] ^ (*a)[x][4]);
  }
  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < 64; z++) {
      u64 r1 = ROL64(c[MOD(x - 1, 5)], 64 - z);
      u64 r2 = ROL64(c[MOD(x + 1, 5)], 64 - MOD(z - 1, 64));
      d[x] = d[x] + ROL64((r1 ^ r2) & 1, z);
    }
  }
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      (*a)[x][y] ^= d[x];
    }
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
static void rho(u64 (*a)[5][5]) {
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
static void pi(u64 (*a)[5][5]) {
  u64 ap[5][5];

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      (*a)[x][y] = ap[MOD((x + 3 * y), 5)][x];
    }
  }
}

//
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
static void chi(u64 (*a)[5][5]) {
  u64 ap[5][5], one = 1, t1, t2, t3;

  memcpy(ap, *a, sizeof(u64) * 5 * 5);
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
static u08 rc(u64 t) {
  u08 m = MOD(t, 255), r1 = 128, r0;

  if (m == 0) return 1;
  for (u64 i = 1; i <= m; i++) {
    r0 = 0;
    r0 ^= MOD(r1, 2);
    r1 ^= MOD(r1, 2) << 4;
    r1 ^= MOD(r1, 2) << 3;
    r1 ^= MOD(r1, 2) << 2;
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
static void iota(u64 (*A)[5][5], u64 ir) {
  u64 r = 0;

  for (u64 j = 0; j <= 6; j++) {r += ROL64(rc(j + 7 * ir), (int)pow(2, j) -1);}
  (*A)[0][0] ^= r;
}

//
// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
static void keccak_p(u08 *sm, u08 (*s)[200]) {
  u64 a[5][5];

  str2state(sm, &a);
  // Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
  for (int ir = 0; ir <= 23; ir++) { // nr = 24; ir = 24 - nr; ir <= 23;
    theta(&a); rho(&a); pi(&a); chi(&a); iota(&a, ir);
  }
  state2str(&a, (*s));
}

//
// Concatenate
static u64 cat(const u08 *x, u64 xl, const u08 *y, const u64 yl, u08 **z) {
  u64 zbil = xl + yl, xl8 = xl / 8, mxl8 = MOD(xl, 8);

  *z = calloc(512, sizeof(u08));
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
static u64 pad10(u64 x, u64 m, u08 **p) {
  long j = MOD((-m - 2), x) + 2;
  int bl = (j) / 8 + (MOD(j, 8) ? 1 : 0);

  *p = calloc(bl, sizeof(u08));
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
static void sponge(u08 *n, int l, u08 **ps) {
  u64 b = 1600, c = 512, len, plen, zl = 0, r = b - SHA3_BITS;
  u08 az[64] = {0}, s[200] = {0}, sc[200] = {0}, sxor[200] = {0};
  u08 *p, *pi, *z, *pad, str[200] = {0};

  len = pad10(r, l, &pad);
  plen = cat(n, l, pad, len, &p);
  for (u64 i = 0; i < plen / r; i++) {
    cat(&p[i * r / 8], r, az, c, &pi);
    for (u64 j = 0; j < b / 8; j++) {sxor[j] = s[j] ^ pi[j];}
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
void lighthash3_hash_new(u08 *n, char *s) {
  u08 *m, z1[] = {2}, *ss = malloc(128 * sizeof(u08));
  u64 d = strlen((char*)n) * 8;

  cat(n, d, z1, 2, &m);
  sponge(m, d + 2, &ss);
  bit2str(ss, s);
  free(ss);
}

// Good link to compare hashes
// https://toolsyep.com/en/hash-generator/sha3-512/

// SHA3-512(M) = KECCAK[1024] (M || 01, 512).

// smurfd =
//SHA2-512 : 555cfc37fc24d4971de9b091ef13401b8c5cb8b5b55804da571fb201cbb4fc5d147ac6f528656456651606546ca42a1070bdfd79d024f3b97dd1bdac7e70f3d1
//SHA3-256 : 8599f8f1d8afcd27ce550b412539a2b911723c6aab8f4419c33b986f48200f32
//SHA3-512 : 5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20

// This code works - SHA3-512
/*
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define BIT 512
#define CPW 16
#define SHA3_ROUNDS 24
#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> (sizeof(uint64_t)*8 - (y))))

#define MSB_U64 ((uint64_t)1 << 63) // avoid 64-bit literal portability concerns
#define SHA3_STATE_BITS  1600
#define SHA3_STATE_BYTES (SHA3_STATE_BITS/8)
#define SHA3_WORD_BYTES sizeof(uint64_t)
#define SHA3_WORD_BITS (SHA3_WORD_BYTES*8)
#define SHA3_STATE_WORDS (SHA3_STATE_BYTES/SHA3_WORD_BYTES)

static const uint8_t Ro[SHA3_ROUNDS] = {
   1,  3,  6, 10, 15, 21,
  28, 36, 45, 55,  2, 14,
  27, 41, 56,  8, 25, 43,
  62, 18, 39, 61, 20, 44
};

static const uint8_t Pi[SHA3_ROUNDS] = {
  10,  7, 11, 17, 18, 3,
   5, 16,  8, 21, 24, 4,
  15, 23, 19, 13, 12, 2,
  20, 14, 22,  9,  6, 1
};

static const uint64_t RoundConstants[24] = {
  0x0000000000000001, 0x0000000000008082,
  0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088,
  0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B,
  0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080,
  0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080,
  0x0000000080000001, 0x8000000080008008,
};

#define THETA(s,i) ((s)[(i)] ^ (s)[(i)+5] ^ (s)[(i)+10] ^ (s)[(i)+15] ^ (s)[(i)+20])

static void sha3f(uint64_t s[SHA3_STATE_WORDS]) {
  uint64_t bc[5];
  uint64_t t;

  for (int round = 0; round < SHA3_ROUNDS; ++round) {
    // Theta
    for (size_t i = 0; i < 5; ++i) {
      bc[i] = THETA(s, i);
      printf("theta : %llu = %llu ^ %llu ^ %llu ^ %llu ^ %llu\n",
        bc[i], (s)[(i)], (s)[(i)+5], (s)[(i)+10], (s)[(i)+15], (s)[(i)+20]);
    }

    for (size_t i = 0; i < 5; ++i) {
      t = bc[(i+4)%5] ^ SHA3_ROTL64(bc[(i+1)%5], 1);
      for (size_t j = 0; j < SHA3_STATE_WORDS; j += 5) {
        s[i+j] ^= t;
      }
    }

    // Rho Pi
    t = s[1];
    for (size_t i = 0; i < SHA3_STATE_WORDS-1; ++i) {
      const uint8_t j = Pi[i];
      bc[0] = s[j];
      s[j] = SHA3_ROTL64(t, Ro[i]);
      t = bc[0];
    }

    // Chi
    for (int j = 0; j < 5; ++j) {
      for (int i = 0; i < 5; ++i) bc[i] = s[i+5*j];
      for (int i = 0; i < 5; ++i) s[i+5*j] ^= ~bc[(i+1)%5] & bc[(i+2)%5];
    }

    // Iota
    s[0] ^= RoundConstants[round];
  }
}

static void fillSaved(const uint8_t **in, size_t *rem, uint64_t *sav, size_t *bi) {
  while ((*rem)-- > 0) {
    *sav |= (uint64_t)(**in) << (*bi * 8);
    ++(*in);
    ++(*bi);
  }
}

// Absorb
void FIPS202_SHA3_Update(const void *inPtr, size_t inSz, uint64_t *ss, uint64_t *sav, size_t *bi, size_t *wi) {
  const uint8_t *in = (const uint8_t *)inPtr;
  const size_t words = inSz / sizeof(uint64_t);
  size_t tail = inSz - words * sizeof(uint64_t);

  printf("words=%zu = %zu / %llu\n", words, inSz, sizeof(uint64_t));

  for (size_t i = 0; i < words; ++i) {
    const uint64_t t = (uint64_t)(in[0]) |
           (uint64_t)(in[1]) << 8*1 |
           (uint64_t)(in[2]) << 8*2 |
           (uint64_t)(in[3]) << 8*3 |
           (uint64_t)(in[4]) << 8*4 |
           (uint64_t)(in[5]) << 8*5 |
           (uint64_t)(in[6]) << 8*6 |
           (uint64_t)(in[7]) << 8*7;
    ss[*wi] ^= t;
    ++(*wi);
    if (*wi == (SHA3_STATE_WORDS - CPW)) {sha3f(ss); *wi = 0;}
    in += sizeof(uint64_t);
  }
  fillSaved(&in, &tail, sav, bi); // finally, save the partial word
}

void FIPS202_SHA3_Final(void *outPtr, uint64_t *ss, uint64_t *sav, size_t *bi, size_t *wi) {
  uint8_t *out = (uint8_t *)outPtr;

  // pad and finish
  ss[*wi] ^= *sav;
  ss[*wi] ^= (uint64_t)(0x06) << (*bi*8);
  ss[SHA3_STATE_WORDS - CPW-1] ^= MSB_U64;
  sha3f(ss);
  memcpy(out, ss, BIT);
}

int main() {
  const char *in = "smurfd";
  size_t bi = 0, wi = 0;
  uint8_t *out = malloc(BIT);
  uint64_t *s = malloc(sizeof(uint64_t)*SHA3_STATE_WORDS);
  uint64_t sav = 0;

  FIPS202_SHA3_Update(in, strlen(in), s, &sav, &bi, &wi);
  FIPS202_SHA3_Final(out, s, &sav, &bi, &wi);
  for (uint64_t i = 0; i < 64; i++) {printf("%.2x", out[i]);} printf("\n");
  free(out);
}
*/
