// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "lightdefs.h"

__extension__ typedef unsigned __int128 uint128;

u64 keys_write(char *fn, uint8_t data[], int type);
int keys_make(uint8_t publ[], uint8_t priv[]);
int keys_secr(const uint8_t pub[], const uint8_t prv[], uint8_t scr[]);
int keys_sign(const uint8_t priv[], uint8_t hash[], uint8_t sign[]);
int keys_vrfy(const uint8_t publ[], const uint8_t hash[], const uint8_t sign[]);
#endif
