//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1
#include <stdint.h>
#include "lightdefs.h"

// lh3 for LightHash3
void lh3new(uint8_t *n, char *ss);
void lh3shake_test();
#endif
