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

uint64_t ROL64(uint64_t a, uint64_t n);
int mod(int n, int M);
void str2state(const uint8_t *S, uint64_t (*A)[5][5]);
void state2str(uint64_t (*A)[5][5], uint8_t *S);
uint8_t rc(uint32_t t);
void theta(uint64_t (*A)[5][5]);
void rho(uint64_t (*A)[5][5]);
void pi(uint64_t (*A)[5][5]);
void chi(uint64_t (*A)[5][5]);
void iota(uint64_t (*A)[5][5], uint32_t ir);
void keccak_p(uint8_t *sm, uint8_t (*S)[200]);
uint32_t concatenate(uint8_t **z, const uint8_t *x, uint32_t xl, const uint8_t *y, uint32_t yl);
uint32_t pad10(uint32_t x, uint32_t m, uint8_t **P);
void sponge(uint8_t *N, uint32_t d, int l, uint8_t **ps);
void keccak(uint8_t *N, int c, int d, unsigned char *S);
#endif
