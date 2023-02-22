#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

// Random
uint64_t lkeys_rnd_next(void);
void lkeys_rnd_init(uint64_t seed);

int lkeys_make_keys(uint64_t publ[KB + 1], uint64_t priv[KB]);
int lkeys_shar_secr(const uint64_t publ[KB + 1], const uint64_t priv[KB],
  uint64_t secr[KB]);
int lkeys_sign(const uint64_t priv[KB], const uint64_t hash[KB],
  uint64_t sign[KB2]);
int lkeys_vrfy(const uint64_t publ[KB + 1], const uint64_t hash[KB],
  const uint64_t sign[KB2]);
#endif
