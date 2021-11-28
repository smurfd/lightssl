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

const uint8_t a1[] = {
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe,
  0xfc, 0x2f
}; // 30

const uint8_t a2_1[] = {
  0x79, 0xbe, 0x66, 0x7e,
  0xf9, 0xdc, 0xbb, 0xac,
  0x55, 0xa0, 0x62, 0x95,
  0xce, 0x87, 0x0b, 0x07,
  0x02, 0x9b, 0xfc, 0xdb,
  0x2d, 0xce, 0x28, 0xd9,
  0x59, 0xf2, 0x81, 0x5b,
  0x16, 0xf8, 0x17, 0x98
}; // 32

const uint8_t a2_2[] = {
  0x48, 0x3a, 0xda, 0x77,
  0x26, 0xa3, 0xc4, 0x65,
  0x5d, 0xa4, 0xfb, 0xfc,
  0x0e, 0x11, 0x08, 0xa8,
  0xfd, 0x17, 0xb4, 0x48,
  0xa6, 0x85, 0x54, 0x19,
  0x9c, 0x47, 0xd0, 0x8f,
  0xfb, 0x10, 0xd4, 0xb8
}; // 32

const uint8_t a3[] = {
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe,
  0xba, 0xae, 0xdc, 0xe6,
  0xaf, 0x48, 0xa0, 0x3b,
  0xbf, 0xd2, 0x5e, 0x8c,
  0xd0, 0x36, 0x41, 0x41
}; // 32

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
