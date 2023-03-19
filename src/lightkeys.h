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
u64 prng_rotate(u64 x, u64 k);
u64 prng_next(void);
void prng_init(u64 seed);

int lkmake_keys(u64 publ[KB + 1], u64 priv[KB], u64 private[DI]);
int lkshar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB], u64 random[DI]);
int lksign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2], u64 k[DI]);
int lkvrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]);
#endif
