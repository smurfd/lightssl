// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

void clr_state(u64 Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = 0;
      }
    }
  }
}

void print_state(u64 Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        printf("%llu ", Ap[x][y][z]);
      }
      printf("\n");
    }
  }
}

void copy_state(u64 A[5][5][64], u64 Ap[5][5][64]) {
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
void str2state(char *S, u64 Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = S[64 * ((5 * y) + x) + z];
      }
    }
  }
}

// Let A denote a state array. The corresponding string representation, denoted by S,
// can be constructed from the lanes and planes of A, as follows:
// For each pair of integers (i, j) such that 0≤i<5 and 0≤j<5, define the string Lane(i, j)
// by Lane(i,j)= A[i,j,0] || A[i,j,1] || A[i,j,2] || ... || A[i,j,w-2] || A[i,j,w-1].
void state2str(u64 A[5][5][64], char *S) {
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
void th(u64 A[5][5][64], u64 Ap[5][5][64]) {
  u64 C[5][64], D[5][64];

  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < 64; z++) {
      C[x][z] = (u64)(A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z]);
      D[x][z] = (u64)(C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % 64]);
    }
  }
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = (u64)(A[x][y][z] ^ D[x][z]);
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
void p(u64 A[5][5][64], u64 Ap[5][5][64]) {
  int x = 1, y = 0, xtmp = 0;

  for (int z = 0; z < 64; z++) {
    Ap[0][0][z] = A[0][0][z];
  }
  for (int t = 0; t < 23; t++) {
    for (int z = 0; z < 64; z++) {
      Ap[x][y][z] = A[x][y][(z - ((t + 1) * (t + 2) / 2)) % 64];
    }
    xtmp = x;
    x = y;
    y = (2 * xtmp + 3 * y) % 5;
  }
}

// Steps:
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′[x, y, z]= A[(x + 3y) mod 5, x, z].
// 2. Return A′.
void pi(u64 A[5][5][64], u64 Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = A[(x + (3 * y)) % 5][x][z];
      }
    }
  }
}

// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
// A′ [x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
// 2. Return A′.
void ex(u64 A[5][5][64], u64 Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = (u64)(A[x][y][z] ^ (u64)((A[(x+1) % 5][y][z] ^ 1) & A[(x+2)%5][y][z]));
      }
    }
  }
}

int el(int t) {
  int R[] = {1,0,0,0,0,0,0,0};
  int m = t % 255, Rp[1601], Rj[8], co = 8;
  if (m == 0) return 1;

  for (int i = 1; i < m; i++) {
    for (int j = 0; j < co; j++) {
      if (co == 8) Rp[j + 1] = R[j];
      else Rp[j + 1] = Rp[j];
    }
    Rp[0] = 0;
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
// 1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let A′[x, y, z] = A[x, y, z].
// 2. Let RC = 0w.
// 3. For j from 0 to l, let RC[2j – 1] = rc(j + 7ir).
// 4. For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ⊕ RC[z].
// 5. Return A′.
void el1(u64 A[5][5][64], int ir, u64 Ap[5][5][64]) {
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
  for (int j = 0; j < 6; j++) RC[(int)pow(2, j) - 1] = el(j + (7 * ir));
  for (int z = 0; z < 64; z++) Ap[0][0][z] = (u64)(Ap[0][0][z] ^ RC[z]);
}

void rnd1(u64 A[5][5][64], int ir, u64 Ap[5][5][64]) {
  u64 Ap1[5][5][64];

  th(A, Ap1);
  p(Ap1, Ap1);
  pi(Ap1, Ap1);
  ex(Ap1, Ap1);
  el1(Ap1, ir, Ap);
}

// Steps:
// 1. Convert S into a state array, A, as described in Sec. 3.1.2.
// 2. For ir from 12 + 2l – nr to 12 + 2l – 1, let A = Rnd(A, ir).
// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
// 4. Return S′.
void keccak_p(int b, int nr, char *S, char *Sp) {
  u64 A[5][5][64], Ap[5][5][64], Ap1[5][5][64];

  str2state(S, A);
  copy_state(A, Ap1);
  for (int ir = 24 - nr; ir < 23; ir++) {
    rnd1(Ap1, ir, Ap);
    copy_state(Ap, Ap1);
  }
  state2str(Ap, Sp);
  Sp[b] = '\0';
}

void keccak_f(int b, char *S, char *Sp) {
  keccak_p(b, 12 + 12, S, Sp);
}

void pad(char *S, int x, int y, char *p) {
  for (int i = x; i < y; i++) {
    p[i-x] = S[i];
  }
  p[y] = '\0';
}

void f(char *S, int b, int r, int d, char *Sr) {
  char ZS[1601];
  int co = 0;

  while (true) {
    char Zp[1601], Zpp[1601];
    if (co == 0) for (int i = 0; i < r; i++) Zp[i] = S[i];
    else for (int i = 0; i < r; i++) Zp[i] = ZS[i];
    co = 1;
    for (int i = 0; i < (int)strlen(Zp); i++) Zpp[i] = Zp[i];
    for (int i = 0; i < (int)strlen(Zp); i++) Zpp[i + (int)strlen(Zp)] = Zp[i];
    if (d <= (int)strlen(Zpp)) {for (int j = 0; j < d; j++) {Sr[j] = Zpp[j];} Sr[d]='\0'; break;}
    else {f(Zpp, b, r, d, ZS);}
  }
}

void sponge(char *N, int r, int b, int d, char *Sr) {
  int c = b - r;
  char S[1601], Pp[1601], Pn[1601], P[1601];

  d = 10; // dunno what d should be, forcing 10 for now
  pad(N, r, d, Pp);
  for (int i = 0; i < (int)strlen(N); i++) P[i] = N[i];
  for (int i = 0; i < (int)strlen(Pp); i++) P[i + (int)strlen(N)] = Pp[i];
  int n = (int)strlen(P) / r;
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < r; j++) {Pn[j + (i * r)] = P[j + (i * r)];}
  }
  Pn[r*n-1]='\0';
  for (int i = 0; i < b; i++) S[i] = 0;
  for (int i = 0; i < n; i++) {
    char sss[1601];
    int pns[1601];
    for (int j = 0; j < (int)strlen(Pn); j++) {pns[j] = Pn[j];}
    for (int j = 0; j < c; j++) pns[j + (int)strlen(Pn)] = 0;
    for (int j = 0; j < b; j++) {sss[j] = S[j] ^ pns[j];}
    f(sss, b, r, d, Sr);
  }
}

// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
void pad10(int x, int m, char *P) {
  int j = (-m - 2) % x;
  for (int i = 0; i < j; i++) Pp[i+1] = 0;
  Pp[0] = 1;
  Pp[j] = 1;
}

void keccak(char *N, int c, int d, char *S) {
  char Pp[1601];

  keccak_p(12, 2, N, Pp);
  pad10(5, c, Pp);
  sponge(Pp, c, 1600, d, S);
}
