// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int str2state(char *S, uint64_t Ap[5][5][64]);
int state2str(uint64_t A[5][5][64], char *S);
int th(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
int p(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
int pi(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
int ex(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
int el(int t);
int el1(uint64_t A[5][5][64], int ir, uint64_t Ap[5][5][64]);
int rnd1(uint64_t A[5][5][64], int ir, uint64_t Ap[5][5][64]);
int keccak_p(int b, int nr, char *S, char *Sp);
int pad(char *S, int x, int y, char *p);
int f(int *S, int b, int *Ss);
int sponge(char *N, int r, int b, int d, char *Sr);
