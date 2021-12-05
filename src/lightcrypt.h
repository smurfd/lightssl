//                                                                            //
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <gmp.h>
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
  mpz_t r1;
  mpz_t r2;
};

union rr {
  struct r r3;
  mpz_t p;
};

struct rrr {
  int uniontype;
  union rr u;
};

struct ellipticcurve {
  char name[10];
  mpz_t p;
  uint8_t a;
  uint8_t b;
  mpz_t g1;
  mpz_t g2;
  mpz_t n;
  uint8_t h;
} curve;

void inverse_mod(mpz_t k, mpz_t pi, mpz_t tmp);
bool is_on_curve(mpz_t point, mpz_t point2);
void point_neg(mpz_t point, mpz_t pr1, mpz_t pr2);
void point_add(mpz_t point1, mpz_t point2, struct rrr *ret);
void scalar_mult(mpz_t kk, mpz_t point, mpz_t point2, mpz_t tt);
void private_key(mpz_t key);
void public_key(mpz_t privkey, mpz_t pubkey);
void lightcrypt_init();

#endif
