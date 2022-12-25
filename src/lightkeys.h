#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

// Random
u64 lkeys_rnd_next(void);
void lkeys_rnd_init(u64 seed);

int lkeys_make_keys(u64 publ[KB + 1], u64 priv[KB]);
int lkeys_shar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB]);
int lkeys_sign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2]);
int lkeys_vrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]);
#endif
