#ifndef LIGHTlkH
#define LIGHTlkH 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

// Random
uint64_t prng_rotate(uint64_t x, uint64_t k);
uint64_t prng_next(void);
void prng_init(uint64_t seed);

int lkmake_keys(uint64_t publ[KB + 1], uint64_t priv[KB]);
int lkshar_secr(const uint64_t publ[KB + 1], const uint64_t priv[KB], uint64_t secr[KB]);
int lksign(const uint64_t priv[KB], const uint64_t hash[KB], uint64_t sign[KB2]);
int lkvrfy(const uint64_t publ[KB + 1], const uint64_t hash[KB], const uint64_t sign[KB2]);
#endif
