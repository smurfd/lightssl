//                                                                                                                    //
#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "lightdefs.h"

u64 keys_write(char *fn, uint8_t data[], int type);
int keys_make(uint8_t publ[KB + 1], uint8_t priv[KB], u64 private[DI]);
int keys_secr(const uint8_t pub[KB + 1], const uint8_t prv[KB], uint8_t scr[KB], u64 r[DI]);
int keys_sign(const uint8_t priv[KB], const uint8_t hash[KB], uint8_t sign[KB2], u64 k[DI]);
int keys_vrfy(const uint8_t publ[KB + 1], const uint8_t hash[KB], const uint8_t sign[KB2]);
#endif
