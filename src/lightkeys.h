#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightdefs.h"

int keys_make_keys(u64 publ[KB + 1], u64 priv[KB]);

u64 prng_rotate(u64 x, u64 k);
u64 prng_next(void);
void prng_init(u64 seed);
#endif
