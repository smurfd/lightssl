//                                                                            //
// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#ifndef LIGHTHASH3_H
#define LIGHTHASH3_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int el(int t);
void clr_state(u64 Ap[5][5][64]);
void print_state(u64 Ap[5][5][64]);
void str2state(char *S, u64 Ap[5][5][64]);
void state2str(u64 A[5][5][64], char *S);
void th(u64 A[5][5][64], u64 Ap[5][5][64]);
void p(u64 A[5][5][64], u64 Ap[5][5][64]);
void pi(u64 A[5][5][64], u64 Ap[5][5][64]);
void ex(u64 A[5][5][64], u64 Ap[5][5][64]);
void el1(u64 A[5][5][64], int ir, u64 Ap[5][5][64]);
void rnd1(u64 A[5][5][64], int ir, u64 Ap[5][5][64]);
void keccak(char *N, int c, int d, char *S);
void keccak_p(int b, int nr, char *S, char *Sp);
void keccak_f(int b, char *S, char *Sp);
void pad(char *S, int x, int y, char *p);
void f(char *S, int b, int r, int d, char *Sr);
void sponge(char *N, int r, int b, int d, char *Sr);
void pad10(int x, int m, int *P);
#endif
