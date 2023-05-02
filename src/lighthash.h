// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

void hash_new(char s[], const uint8_t *n);
void hash_shake_new(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen);
#endif
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
