//                                                                            //
#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdbool.h>
#include "lightdefs.h"

int lkrand(u64 h[KB], u64 k[KB]);
int lkmake_keys(u64 publ[KB + 1], u64 priv[KB], u64 private[DI]);
int lkshar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB], u64 random[DI]);
int lksign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2], u64 k[DI]);
int lkvrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]);
#endif
