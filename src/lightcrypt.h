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

struct tuple {
  mpz_t p1;
  mpz_t p2;
  bool empty;
};

struct ellipticcurve {
  char name[10];
  mpz_t p;
  uint8_t a;
  uint8_t b;
  mpz_t n;
  uint8_t h;
  struct tuple g;
} curve;

void lightcrypt_init();
void inverse_mod(mpz_t k, mpz_t pi, mpz_t *tmp);
bool is_on_curve(struct tuple point);
void point_neg(struct tuple point, struct tuple *rest);
void point_add(struct tuple p1, struct tuple p2, struct tuple *r1);
void scalar_mult(mpz_t kk, struct tuple point, struct tuple *tt);
void private_key(mpz_t *key);
void public_key(mpz_t privkey, struct tuple *pubkey);

#endif
