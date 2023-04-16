//                                                                                                                    //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

void hash_new(char *ss, const uint8_t *n);
void hash_shake_xof(uint8_t *sm);
void hash_shake_touch(uint8_t *sm, uint8_t s[], uint8_t *next, bool upd);
#endif
