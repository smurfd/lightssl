//                                                                            //
#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "lightdefs.h"

u64 lkwrite(char *fn, uint8_t c[], int type);
int lkmake_keys(u64 publ[KB + 1], u64 priv[KB], u64 private[DI]);
int lkshar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB],
  u64 random[DI]);
int lksign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2], u64 k[DI]);
int lkvrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]);
#endif
