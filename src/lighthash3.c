// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Imitate pythons %. -1 % 5 = 4, not -1
int mod(int n, int M) {return ((n % M) + M) % M;}

void clr_state(uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = 0;
      }
    }
  }
}

void print_state(uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        printf("%llu ", Ap[x][y][z]);
      }
      printf("\n");
    }
  }
}

void copy_state(uint64_t A[5][5][64], uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = A[x][y][z];
      }
    }
  }
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
void str2state(char *S, uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        int len = 64 * ((5 * y) + x) + z;
        if (len <= (int)strlen(S)) Ap[x][y][z] = S[len];
        else Ap[x][y][z] = 0;
      }
    }
  }
}

// Let A denote a state array. The corresponding string representation, denoted by S,
// can be constructed from the lanes and planes of A, as follows:
// For each pair of integers (i, j) such that 0≤i<5 and 0≤j<5, define the string Lane(i, j)
// by Lane(i,j)= A[i,j,0] || A[i,j,1] || A[i,j,2] || ... || A[i,j,w-2] || A[i,j,w-1].
void state2str(uint64_t A[5][5][64], char *S) {
  int count = 0;

  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        S[count] = A[x][y][z];
        count = count + 1;
      }
    }
  }
  S[64*5*5] = '\0';
}

// 1. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
// C[x, z] = A[x, 0, z] ⊕ A[x, 1, z] ⊕ A[x, 2, z] ⊕ A[x, 3, z] ⊕ A[x, 4, z].
// 2. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
// D[x, z] = C[(x1) mod 5, z] ⊕ C[(x+1) mod 5, (z – 1) mod w].
// 3. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z] = A[x, y, z] ⊕ D[x, z].
void th(uint64_t A[5][5][64], uint64_t Ap[5][5][64]) {
  uint64_t C[5][64], D[5][64];

  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < 64; z++) {
      C[x][z] = (A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z]);
      //printf("c=%llu = a0=%llu xor a1=%llu xor a2=%llu xor a3=%llu xor a4=%llu :: %d %d\n", C[x][z], A[x][0][z], A[x][1][z], A[x][2][z], A[x][3][z], A[x][4][z], x, z);
    }
  }
  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < 64; z++) {
      D[x][z] = (C[(int)mod((x - 1), 5)][z] ^ C[(int)mod((x + 1), 5)][(int)mod((z - 1), 64)]);
      //printf("d=%llu = c=%llu xor c=%llu  :: %d %d %d\n", D[x][z], C[(int)mod((x - 1), 5)][z], C[(int)mod((x + 1), 5)][(int)mod((z - 1), 64)], mod((x - 1), 5), mod((x + 1), 5), mod((z - 1), 64));
    }
  }
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = (A[x][y][z] ^ D[x][z]);
        //printf("Ap=%llu, A=%llu XOR D=%llu\n", Ap[x][y][z], A[x][y][z], D[x][z]);
      }
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
void p(uint64_t A[5][5][64], uint64_t Ap[5][5][64]) {
  int x = 1, y = 0, xtmp = 0;

  for (int z = 0; z < 64; z++) {Ap[0][0][z] = A[0][0][z];}
  for (int t = 0; t < 23; t++) {
    for (int z = 0; z < 64; z++) {
      Ap[x][y][z] = A[x][y][mod((z - ((t + 1) * (t + 2) / 2)), 64)];
      //printf("ap=%llu A=%llu, %d :: %d %d %d\n",Ap[x][y][z],A[x][y][mod((z - ((t + 1) * (t + 2) / 2)), 64)], mod((z - ((t + 1) * (t + 2) / 2)), 64), x, y, z);
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
void pi(uint64_t A[5][5][64], uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = A[mod((x + (3 * y)), 5)][x][z];
      }
    }
  }
}

// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
void ex(uint64_t A[5][5][64], uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = (A[x][y][z] ^ ((A[mod((x + 1), 5)][y][z] ^ 1) & A[mod((x + 2), 5)][y][z]));
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
int el(int t) {
  int R[] = {1,0,0,0,0,0,0,0};
  int m = mod(t, 255), Rp[1601], Rpp[1601], Rj[8], co = 7;

  if (m == 0) return 1;
  for (int i = 1; i < m; i++) {
    Rpp[0] = 0;
    for (int j = 0; j < co; j++) {
      if (co == 7) Rpp[j + 1] = R[j];
      else Rpp[j + 1] = Rp[j];
    }
    for (int j = 0; j < co; j++) Rp[j] = Rpp[j];
    co++;
    Rp[0] = Rp[0] ^ Rp[8];
    Rp[4] = Rp[4] ^ Rp[8];
    Rp[5] = Rp[5] ^ Rp[8];
    Rp[6] = Rp[6] ^ Rp[8];
    for (int j = 0; j < 8; j++) Rj[j] = Rp[j];
  }
  return Rj[0];
}

// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and
//      0 ≤ z < w, let A′[x, y, z] = A[x, y, z].
// 2. Let RC = 0w.
// 3. For j from 0 to l, let RC[2j – 1] = rc(j + 7ir).
// 4. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ⊕ RC[z].
// 5. Return A′.
void el1(uint64_t A[5][5][64], int ir, uint64_t Ap[5][5][64]) {
  // log2(64) = 6
  int RC[64];

  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = A[x][y][z];
      }
    }
  }
  for (int i = 0; i < 64; i++) RC[i] = 0;
  for (int j = 0; j < 6; j++) {RC[(int)pow(2, j) - 1] = el(j + (7 * ir));}
  for (int z = 0; z < 64; z++) Ap[0][0][z] = Ap[0][0][z] ^ RC[z];
}

// Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
void rnd1(uint64_t A[5][5][64], int ir, uint64_t Ap[5][5][64]) {
  th(A, Ap);
  p(Ap, Ap);
  pi(Ap, Ap);
  ex(Ap, Ap);
  el1(Ap, ir, Ap);
}

// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
void keccak_p(int b, int nr, char *S, char *Sp) {
  uint64_t A[5][5][64];

  str2state(S, A);
  for (int ir = 24 - nr; ir < 23; ir++) {
    rnd1(A, ir, A);
  }
  state2str(A, Sp);
  Sp[b] = '\0';
}

void keccak_f(int b, char *S, char *Sp) {
  keccak_p(b, 12 + 12, S, Sp);
}

void pad(char *S, int x, int y, char *p) {for (int i = x; i < y; i++) p[x-i] = S[i]; p[y]='\0';}

void f(char *S, int b, int r, int d, char *Sr) {
  char ZS[1601], Zp[1601], Zpp[1601];

  for (int i = 0; i < r; i++) Zp[i] = S[i];
  while (true) {
    for (int i = 0; i < (int)strlen(Zp); i++) Zpp[i] = Zp[i];
    for (int i = 0; i < (int)strlen(Zp); i++) Zpp[i + (int)strlen(Zp)] = Zp[i];
    if (d <= (int)strlen(Zpp)) {for (int j = 0; j < d; j++) {Sr[j] = Zpp[j];} Sr[d]='\0'; break;}
    else f(Zpp, b, r, d, ZS);
    for (int i = 0; i < r; i++) Zp[i] = ZS[i];
  }
}

// Steps:
// 1. Let P=N || pad(r, len(N)).
// 2. Let n = len(P)/r.
// 3. Letc=b-r.
// 4. Let P0, ... , Pn-1 be the unique sequence of strings of length r such
//      that P = P0 || ... || Pn-1.
// 5. Let S=0b.
// 6. For i from 0 to n-1, let S=f(S ⊕ (Pi || 0c)).
// 7. Let Z be the empty string.
// 8. Let Z=Z || Truncr(S).
// 9. If d ≤ |Z|, then return Trunc d (Z); else continue.
// 10. Let S=f(S), and continue with Step 8.
void sponge(char *N, int r, int b, int d, char *Sr) {
  char Pp[1601], Pn[1601], P[1601], sss[1601];
  int c = b - r, pns[1601];

  pad(N, r, strlen(N), Pp);
  for (int i = 0; i < (int)strlen(N); i++) P[i] = N[i];
  for (int i = 0; i < (int)strlen(Pp); i++) P[i + (int)strlen(N)] = Pp[i];
  int n = (int)strlen(P) / r;

  for (int i = 0; i < n; i++) {
    for (int j = 0; j < r; j++) {Pn[j + (i * r)] = P[j + (i * r)];}
  }
  Pn[r*n-1]='\0';
  for (int i = 0; i < b; i++) sss[i] = 0;
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < (int)strlen(Pn); j++) {pns[j] = Pn[j];}
    for (int j = 0; j < c; j++) pns[j + (int)strlen(Pn)] = 0;
    for (int j = 0; j < b; j++) {sss[j] = sss[j] ^ pns[j];}
    f(sss, b, r, d, sss);
  }
  for (int i = 0; i < (int)strlen(sss); i++) Sr[i] = sss[i];
}

// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
void pad10(int x, int m, char *P) {
  int j = mod((-m - 2), x);

  if (j < 0) j = j * -1;
  P[0] = 1;
  for (int i = 0; i < j; i++) P[i + 1] = 0;
  P[j] = 1;
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
void keccak(char *N, int c, int d, char *S) {
  char Pp[1601];

  keccak_p(512, 24, N, Pp);
  pad10(512, c, Pp);
  sponge(Pp, c, 12, d, S);
}

// SHA3-512(M) = KECCAK[1024] (M || 01, 512).
