//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

// lh3 for LightHash3
void hash_new(uint8_t *n, char *ss);
void bit2str(uint8_t *ss, char *s);
void hash_shake_xof(uint8_t *sm, uint8_t (*s)[200]);
uint8_t hash_shake_touch(uint8_t *sm, uint8_t s[200], uint8_t next, bool upd);
#endif
