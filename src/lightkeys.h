// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTKEYS_H
#define LIGHTKEYS_H 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "lightdefs.h"

u64 keys_write(char *fn, uint8_t data[], int type);
int keys_make(uint8_t publ[], uint8_t priv[], u64 private[]);
int keys_secr(const uint8_t pub[], const uint8_t prv[], uint8_t scr[], u64 r[]);
int keys_sign(const uint8_t priv[], const uint8_t hash[], uint8_t sign[], u64 k[]);
int keys_vrfy(const uint8_t publ[], const uint8_t hash[], const uint8_t sign[]);
#endif
