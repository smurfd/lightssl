//                                                                            //
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "defs.h"

// Read: https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
// Read: https://andrea.corbellini.name/2015/05/23/elliptic-curve-cryptography-finite-fields-and-discrete-logarithms/
// Read: https://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa/
// Read: https://andrea.corbellini.name/2015/06/08/elliptic-curve-cryptography-breaking-security-and-a-comparison-with-rsa/
// (maby the python scripts atleast make sense? or the pictures?)

// FML
// https://raw.githubusercontent.com/andreacorbellini/ecc/master/scripts/ecdsa.py
// https://raw.githubusercontent.com/andreacorbellini/ecc/master/scripts/ecdhe.py


// https://github.com/ARMmbed/mbedtls

// went back to port the ecdhe.py

#ifndef LIGHTCRYPT_H
#define LIGHTCRYPT_H 1

// FIXME: better struct names
struct r {
  uint64_t *r1;
  uint64_t *r2;
};

union rr {
  struct r r3;
  uint64_t *p;
};

struct rrr {
  int uniontype;
  union rr u;
};

struct ellipticcurve {
  char name[10];
  uint8_t p[30];
  uint8_t a;
  uint8_t b;
  uint8_t g1[32];
  uint8_t g2[32];
  uint8_t n[32];
  uint8_t h;
} curve;

uint64_t inverse_mod(uint64_t k, uint64_t p);
bool is_on_curve(uint64_t* point);
struct rrr point_neg(uint64_t *point);
void point_add(uint64_t *point1, uint64_t *point2, struct rrr *ret);
struct rrr *scalar_mult(uint64_t k, struct rrr *p1, struct rrr *ret);
void private_key(uint8_t *ret);
void public_key(uint8_t *pk, struct rrr *ret);
void lightcrypt_init();

#endif
