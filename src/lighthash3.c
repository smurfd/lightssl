// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w,
// A[x, y, z] = S [w(5y + x) + z].
// For example, if b= 1600, so that w= 64, then
void str2state(char *S, uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = S[64 * (5 * y + x) + z];
      }
    }
  }
}

void state2str(uint64_t A[5][5][64], char *S) {
  int count = 0;
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        S[count++] = A[x][y][z];
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
      C[x][z] = A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z];
      D[x][z] = C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % 64];
    }
  }
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = A[x][y][z] ^ D[x][z];
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
  int x = 0, y = 0, xtmp = 0;
  for (int z = 0; z < 64; z++) {
    Ap[0][0][z] = A[0][0][z];
  }

  for (int t = 0; t < 24; t++) {
    for (int z = 0; z < 64; z++) {
      Ap[x][y][z] = A[x][y][(z - (t + 1) * (t + 2) / 2) % 64];
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
void pi(uint64_t A[5][5][64], uint64_t Ap[5][5][64]) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < 64; z++) {
        Ap[x][y][z] = A[(x+ 3 * y) % 5][x][z];
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
        Ap[x][y][z] = A[x][y][z] ^ ((A[(x+1) % 5][y][z] ^ 1)*A[(x+2)%5][y][z]);
      }
    }
  }
}

int el(int t) {
  int R[] = {1,0,0,0,0,0,0,0};
  int m = t % 255;
  int *Rp = malloc(t * sizeof(int));
  int Rj[8];
  int co = 8;
  if (m == 0) return 1;

  for (int i = 1; i < m; i++) {
    Rp[0] = 0;
    for (int j = 0; j < co; j++) Rp[j + 1] = R[j + 1];
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
  for (int j = 0; j < 6; j++) RC[(int)pow(2, j) - 1] = el(j + (7 * ir));
  for (int z = 0; z < 64; z++) Ap[0][0][z] = Ap[0][0][z] ^ RC[z];
}

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
  uint64_t A[5][5][64], Ap[5][5][64];
  str2state(S, A);
  for (int ir = 12 + 12 - nr; ir < 12 + 12-1; ir++) {
    rnd1(A, ir, Ap);
  }
  state2str(Ap, Sp);
  Sp[b] = '\0';
}

void keccak_f(int b, char *S, char *Sp) {
  keccak_p(b, 12 + 12, S, Sp);
}

void pad(char *S, int x, int y, char *p) {for (int i = x; i < y; i++) p[x-i] = S[i];}

void f(char *S, int b, int *Ss) {
  char *tmp = S;
  int *tmpi = Ss;
  int bb = b;
  if (tmp || tmpi || bb) {}
} // Figure out what this should do

void sponge(char *N, int r, int b, int d, char *Sr) {
  int S[b], Sp[b], c = b - r;
  char *Pp = malloc(strlen(N));
  char **Pn = malloc(r * strlen(N));
  pad(N, r, strlen(N), Pp);
  char *P = malloc(strlen(Pp) + strlen(N));

  for (uint64_t i = 0; i < strlen(Pp); i++) P[i] = Pp[i];
  for (uint64_t i = 0; i < strlen(N); i++) P[i + strlen(Pp)] = N[i];
  int n = strlen(P) / r;

  for (int i = 0; i < n; i++)
    for (int j = 0; j < r; j++) Pn[i][j] = P[j + (i * r)];

  for (int i = 0; i < b; i++) S[i] = 0;
  for (int i = 0; i < n - 1; i++) {
    char *sss = malloc(b * r * c * sizeof(int));
    int *pns = malloc(strlen(*Pn) * c * sizeof(int));
    for (uint64_t j = 0; j < strlen(Pn[i]); j++) pns[j] = Pn[i][j];
    for (int j = 0; j < c; j++) pns[c + j] = 0;
    for (int j = 0; j < b; j++) {sss[j] = sss[j] ^ pns[j];}
    f(sss, b, Sp);
    free(pns);
    free(sss);
  }
  while (true) {
    char *Z = malloc(b);
    char *Zp = malloc(b);
    char *Zpp = malloc(b);

    for (int i = 0; i < r; i++) Zp[i] = S[i];
    for (uint64_t i = 0; i < strlen(Z); i++) Zpp[i] = Z[i];
    for (uint64_t i = 0; i < strlen(Zp); i++) Zpp[i + strlen(Zp)] = Zp[i];
    if (d <= (int)strlen(Zpp)) {for (int j = 0; j < d; j++) {Sr[j] = Zpp[j]; Sr[d]='\0'; break;}}
    else f(Zpp, b, S);
    free(Zpp);
    free(Zp);
    free(Z);
  }
  free(Pn);
  free(Pp);
  free(P);
}

// Steps:
// 1. Let j = (– m – 2) mod x.
// 2. Return P = 1 || 0j || 1.
void pad10(int x, int m, int *P) {
  int j = (-m - 2) % x;
  P[0] = 1;
  for (int i = 0; i < j; i++) P[i+1] = 0;
  P[j] = 1;
}
