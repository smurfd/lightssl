// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef uint8_t u08;
typedef uint64_t u64;

// Imitate pythons %. -1 % 5 = 4, not -1
static int mod(int n, int M) {return ((n % M) + M) % M;}

static u64 ROL64(u64 a, u64 n) {
  if (mod(n, 64) != 0) return (a << (mod(n, 64))) ^ (a >> (64 - (mod(n, 64))));
  return a;
}

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
static void str2state(const u08 *S, u64 (*A)[5][5]) {
  u64 lane;

  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      lane = 0;
      for (int z = 0; z < 8; z++) {
        u64 len = 8 * (5 * y + x) + z;
        lane += ROL64((u64) S[len], z*8);
      }
      (*A)[x][y] = lane;
    }
  }
}

// Let A denote a state array. The corresponding string representation, denoted by S,
// can be constructed from the lanes and planes of A, as follows:
// For each pair of integers (i, j) such that 0≤i<5 and 0≤j<5, define the string Lane(i, j)
// by Lane(i,j)= A[i,j,0] || A[i,j,1] || A[i,j,2] || ... || A[i,j,w-2] || A[i,j,w-1].
static void state2str(u64 (*A)[5][5], u08 *S) {
  int count = 0;

  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      for (int z = 0; z < 8; z++) {
        S[count] = (u08) (ROL64((*A)[x][y], 64 - z * 8) & (u64) 255);
        count++;
      }
    }
  }
}

// 1. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
// C[x, z] = A[x, 0, z] ⊕ A[x, 1, z] ⊕ A[x, 2, z] ⊕ A[x, 3, z] ⊕ A[x, 4, z].
// 2. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
// D[x, z] = C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z – 1) mod w].
// 3. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z] = A[x, y, z] ⊕ D[x, z].
static void theta(u64 (*A)[5][5]) {
  u64 C[5], D[5] = {0}, xor;

  for (int x = 0; x < 5; x++) {
    C[x] = ((*A)[x][0] ^ (*A)[x][1] ^ (*A)[x][2] ^ (*A)[x][3] ^ (*A)[x][4]);
  }
  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < 64; z++) {
      u64 r1 = ROL64(C[mod(x - 1, 5)], 64 - z);
      u64 r2 = ROL64(C[mod(x + 1, 5)], 64 - mod(z - 1, 64));
      xor = r1 ^ r2;
      xor &= 1;
      D[x] += ROL64(xor, z);
    }
  }
  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      (*A)[x][y] ^= D[x];
    }
  }
}

// Steps:
// 1. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A[0, 0, z].
// 2. Let (x, y) = (1, 0).
// 3. For t from 0 to 23:
// a. for all z such that 0 ≤ z < w, let A′[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod w];
// b. let (x, y) = (y, (2x + 3y) mod 5).
// 4. Return A′.
static void rho(u64 (*A)[5][5]) {
  int x = 1, y = 0, xtmp = 0;
  u64 Ap[5][5], cb;

  memcpy(Ap, *A, sizeof(u64) * 5 * 5);
  for (int t = 0; t < 24; t++) {
    (*A)[x][y] = 0;
    for (int z = 0; z < 64; z++) {
      cb = ROL64(Ap[x][y], 64 - mod((z - (t + 1)*(t + 2) / 2), 64));
      cb &= 1;
      cb = ROL64(cb, z);
      (*A)[x][y] += cb;
    }
    xtmp = x;
    x = y;
    y = mod((2 * xtmp + 3 * y), 5);
  }
}

// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z]= A[(x + 3y) mod 5, x, z].
// 2. Return A′.
static void pi(u64 (*A)[5][5]) {
  u64 Ap[5][5];

  memcpy(Ap, *A, sizeof(u64) * 5 * 5);
  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      (*A)[x][y] = Ap[mod((x + 3 * y), 5)][x];
    }
  }
}

// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
static void chi(u64 (*A)[5][5]) {
  u64 Ap[5][5], one = 1, t1, t2, t3;

  memcpy(Ap, *A, sizeof(u64) * 5 * 5);
  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      (*A)[x][y] = 0;
      for (int z = 0; z < 64; z++) {
        t1 = Ap[x][y] & ROL64(one, z); // A[x,y,z]
        t2 = (Ap[mod(x+1, 5)][y] & ROL64(one, z)) ^ ROL64(one, z); // A[(x+1) mod 5, y, z] XOR 1
        t3 = Ap[mod(x+2, 5)][y] & ROL64(one, z); // A[(x+2) mod 5, y, z]
        (*A)[x][y] += t1 ^ (t2 & t3);
      }
    }
  }
}

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
  u64 m = mod(t, 255);
  u08 R = 0x80, R0;

  if (m == 0) return 1;
  for (u64 i = 1; i <= m; i++) {
    R0 = 0;
    R0 ^= (R & 1);
    R ^= (R & 0x1) << 4;
    R ^= (R & 0x1) << 3;
    R ^= (R & 0x1) << 2;
    R >>= 1;
    R ^= R0 << 7;
  }
  return R >> 7;
}

// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and
//      0 ≤ z < w, let A′[x, y, z] = A[x, y, z].
// 2. Let RC = 0w.
// 3. For j from 0 to l, let RC[2j – 1] = rc(j + 7ir).
// 4. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ⊕ RC[z].
// 5. Return A′.
static void iota(u64 (*A)[5][5], u64 ir) {
  u64 RC = 0;

  for (u64 j = 0; j <= 6; j++) {
    RC += ROL64(rc(j + 7 * ir), (int)pow(2, j)-1);
  }
  (*A)[0][0] ^= RC;
}

// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
static void keccak_p(u08 *sm, u08 (*S)[200]) {
  u64 A[5][5];
  int nr = 24;

  str2state(sm, &A);
  for (int ir = 24 - nr; ir <= 23; ir++) {
    // Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
    theta(&A);
    rho(&A);
    pi(&A);
    chi(&A);
    iota(&A, ir);
  }
  state2str(&A, (*S));
}

static u64 cat(u08 **z, const u08 *x, u64 xl, const u08 *y, const u64 yl) {
  u64 zbil = xl + yl, xl8 = xl / 8, mxl8 = mod(xl, 8);

  *z = calloc(256, sizeof(u08));
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

// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
static u64 pad10(u64 x, u64 m, u08 **P) {
  long j = mod((-m - 2), x);
  int bl = (2+j)/8 + (mod(2+j, 8) ? 1 : 0);

  *P = calloc(bl, sizeof(u08));
  (*P)[0] |= 1;
  (*P)[bl-1] |= (1 << mod(j+1, 8));
  return j+2;
}

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
static void sponge(u08 *N, u64 d, int l, u08 **ps) {
  u64 b = 1600, c = 512, len, plen, zl = 0, r = b - d;
  u08 az[64] = {0}, s[200] = {0}, sc[200] = {0}, sxor[200] = {0};
  u08 *p, *pi, *z, *pad, str[200] = {0};

  len = pad10(r, l, &pad);
  plen = cat(&p, N, l, pad, len);
  for (u64 i = 0; i < plen / r; i++) {
    cat(&pi, &p[i * r/8], r, az, c); // P_i || 0^c
    for (u64 j = 0; j < b/8; j++) {sxor[j] = s[j] ^ pi[j];} // S XOR P_i || 0^c
    free(pi);
    keccak_p(sxor, &s); // f(S XOR (P_i || 0^c))
  }

  while (true) {
    memcpy(str, s, r/8);
    zl = cat(&z, z, zl, str, r); // Z = Z || Trunc_r(S)
    if (d <= zl) {memcpy((*ps), z, 512/8); break;}
    memcpy(sc, s, b/8);
    keccak_p(sc, &s);
  }
  free(pad);
  free(p);
  free(z);
}

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
void keccak(u08 *N, int c, int d, u08 *S) {
  u08 *M, z1[] = {0x02};

  cat(&M, N, d, z1, 2);
  sponge(M, c, d+2, &S);
}

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
