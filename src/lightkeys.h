#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

// Random
void lkrnd_init(uint64_t seed);
uint64_t lkrnd_next(void);

int lkmake_keys(uint64_t publ[KB + 1], uint64_t priv[KB]);
int lkshar_secr(const uint64_t publ[KB+1],const uint64_t priv[KB],uint64_t secr[KB]);
int lksign(const uint64_t priv[KB], const uint64_t hash[KB],uint64_t sign[KB2]);
int lkvrfy(const uint64_t publ[KB+1],const uint64_t hash[KB],const uint64_t sign[KB2]);
#endif
