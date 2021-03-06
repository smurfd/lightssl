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
big *curve_p;
u08 curve_a;
u08 curve_b;
big *curve_g1;
big *curve_g2;
big *curve_n;
u08 curve_h;

void lc_random(big **p);
void lc_getrandstr(int len, char *ret);
void lc_privkey(big **privkey);
void lc_publkey(big *privkey, big **pub1, big **pub2);
void lc_point_mul(big *key, big *p1, big *p2, big **ret1, big **ret2);
void lc_point_neg(big *p1, big *p2, big **ret1, big **ret2);
void lc_point_add(big *p1, big *p2, big *p3, big *p4, big **ret1, big **ret2);
void lc_inverse_mod(big *key, big *point, big **ret);
bool lc_on_curve(big *p1, big *p2);
// Crypt
void lc_init();

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
