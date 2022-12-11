//                                                                            //
// Implemented from:
// http://dx.doi.org/10.6028/NIST.FIPS.202
#ifndef LIGHTHASH3_H
#define LIGHTHASH3_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lightdefs.h"

#define SHA3_BITS 1024 // SHA3-256 = 512, SHA3-512 = 1024 (default)

void lighthash3_hash_new(u08 *n, char *ss);
#endif
