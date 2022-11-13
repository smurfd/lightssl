#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

// Random
u32 prng_rotate(u32 x, u32 k);
u32 prng_next(void);
void prng_init(u32 seed);

int keys_make_keys(u64 publ[KB + 1], u64 priv[KB]);
int keys_shar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB]);
int keys_sign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB * 2]);
int keys_vrfy(const u64 publ[KB+1], const u64 hash[KB], const u64 sign[KB*2]);
#endif
