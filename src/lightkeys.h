//                                                                            //
#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "lightdefs.h"

u64 keys_write(char *fn, uint8_t data[], int type);
int keys_make(u64 publ[KB + 1], u64 priv[KB], u64 private[DI]);
int keys_secr(const u64 pub[KB + 1], const u64 prv[KB], u64 scr[KB], u64 r[DI]);
int keys_sign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2], u64 k[DI]);
int keys_vrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]);
#endif
