//                                                                            //
#ifndef LIGHTCRYPT_H
#define LIGHTCRYPT_H 1

#include "lightbig.h"
#include "lightdefs.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *curve_name;
bigint_t *curve_p;
uint8_t curve_a;
uint8_t curve_b;
bigint_t *curve_g1;
bigint_t *curve_g2;
bigint_t *curve_n;
uint8_t curve_h;

void lightcrypt_random(bigint_t **p);
void lightcrypt_getrandstr(int len, char *ret);
void lightcrypt_privkey(bigint_t **privkey);
void lightcrypt_publkey(bigint_t *privkey, bigint_t **pub1, bigint_t **pub2);
void lightcrypt_point_mul(bigint_t *key, bigint_t *point1, bigint_t *point2,
  bigint_t **ret1, bigint_t **ret2);
void lightcrypt_point_neg(
  bigint_t *point1, bigint_t *point2, bigint_t **ret1, bigint_t **ret2);
void lightcrypt_point_add(bigint_t *point1, bigint_t *point2, bigint_t *point3,
  bigint_t *point4, bigint_t **ret1, bigint_t **ret2);

// Crypt
void lightcrypt_init();

#endif

// Read:
// https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
// Read:
// https://andrea.corbellini.name/2015/05/23/elliptic-curve-cryptography-finite-fields-and-discrete-log
// Read:
// https://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa/
// Read:
// https://andrea.corbellini.name/2015/06/08/elliptic-curve-cryptography-breaking-security-and-a-compar
// (maby the python scripts atleast make sense? or the pictures?)

// FML
// https://raw.githubusercontent.com/andreacorbellini/ecc/master/scripts/ecdsa.py
// https://raw.githubusercontent.com/andreacorbellini/ecc/master/scripts/ecdhe.py

// https://github.com/ARMmbed/mbedtls

// went back to port the ecdhe.py
