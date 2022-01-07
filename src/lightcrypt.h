//                                                                            //
#ifndef LIGHTCRYPT_H
#define LIGHTCRYPT_H 1

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "lightbig.h"
#include "lightdefs.h"

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

typedef struct {
  bigint_t *p1;
  bigint_t *p2;
  bool empty;
} bigtup_t;

struct curve {
  char name[10];
  bigint_t *p;
  uint8_t a;
  uint8_t b;
  bigint_t *n;
  uint8_t h;
  bigtup_t *g;
} curve_t;

void lightcrypt_init();
void lightcrypt_rand(bigint_t **p);
void lightcrypt_rand_t(bigtup_t **p);
void lightcrypt_privkey(bigint_t **privkey);
void lightcrypt_pubkey(bigint_t *privkey, bigtup_t **pubkey);
void lightcrypt_point_mul(bigint_t *key, bigtup_t *point, bigtup_t **ret);
void lightcrypt_point_add(bigtup_t *point1, bigtup_t *point2, bigtup_t **ret);
void lightcrypt_point_neg(bigtup_t *point, bigtup_t **ret);
void lightcrypt_point_imd(bigtup_t *key, bigtup_t *point, bigtup_t **ret);
bool lightcrypt_oncurve(bigtup_t *point);
#endif
