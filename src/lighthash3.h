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

typedef uint8_t u08;
typedef uint64_t u64;

void keccak(u08 *N, int c, int d, u08 *S);
#endif
