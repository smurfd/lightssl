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
void clr_state(uint64_t Ap[5][5][64]);
void print_state(uint64_t Ap[5][5][64]);
void str2state(char *S, uint64_t Ap[5][5][64]);
void state2str(uint64_t A[5][5][64], char *S);
void theta(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
void rho(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
void pi(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
void chi(uint64_t A[5][5][64], uint64_t Ap[5][5][64]);
void iota(uint64_t A[5][5][64], int ir, uint64_t Ap[5][5][64]);
void rnd1(uint64_t A[5][5][64], int ir, uint64_t Ap[5][5][64]);
void keccak(char *N, int c, int d, char *S);
void keccak_p(int b, int nr, char *S, char *Sp);
void keccak_f(int b, char *S, char *Sp);
void pad(char *S, int x, int y, char *p);
void f(char *S, int b, int r, int d, char *Sr);
void sponge(char *N, int r, int b, int d, char *Sr);
void pad10(int x, int m, int *P);
#endif
