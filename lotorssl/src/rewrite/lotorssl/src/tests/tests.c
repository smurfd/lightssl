#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../ecc.h"
#include "../ecdsa.h"

uint8_t test_ecdsa(void) {
  // Test vectors: elliptic curve domain parameters, short Weierstrass model y^2 = x^3 + ax + b (mod N)
  long d = 0, h = 0x789abcde, sets[10][6] = {
    // a,   b,  modulus N, base point G, order(G, E), cofactor
    {355, 671, 1073741789, 13693, 10088, 1073807281},
    {  0,   7,   67096021,  6580,   779,   16769911}, // 4
    { -3,   1,     877073,     0,     1,     878159},
    {  0,  14,      22651,    63,    30,        151}, // 151
    {  3,   2,          5,     2,     1,          5},
    {  0,   7,   67096021,  2402,  6067,   33539822}, // 2 // ecdsa may fail if... the base point is of composite order
    {  0,   7,   67096021,  6580,   779,   67079644}, // 1 // the given order is a multiple of the true order
    {  0,   7,     877069,     3, 97123,     877069},      // the modulus is not prime (deceptive example)
    { 39, 387,      22651,    95,    27,      22651},      // fails if the modulus divides the discriminant
  };
  curve e;
  // Digital signature on message hash h, set d > 0 to simulate corrupted data
  for (int i = 0; i < 5; i++) { // we run just the 1st 5 stable tests
    if (curve_init(&e, sets[i])) {
      assert(ecdsa(h, d, &e) == 0);
    } else {printf("oops\n");}
  }
  return 1;
}

uint8_t test_ecdsa2(void) {
  long d = 0, h = 0xdeadbeef0, set[6] = {3, 2, 5, 2, 1, 5};
  curve e;
  if (curve_init(&e, set)) {
    assert(ecdsa(h, d, &e) == 0);
  } else printf("oops\n");
  return 1;
}

uint8_t test_ecdsaloop(void) {
  long d = 0, h = 0xdeadbeef, set[6] = {3, 2, 5, 2, 1, 5};
  curve e;
  for (int i = 0; i < 1000000; i++)
  if (curve_init(&e, set)) {
    assert(ecdsa(h, d, &e) == 0);
  } else printf("oops\n");
  return 1;
}

uint8_t test_ecc(void) {
  ecc();
  return 1;
}

int main(int argc, char** argv) {
  uint8_t ret = 1;
  if (argc == 1) { // When run without arguments or in CI
    ret &= test_ecc();
    ret &= test_ecdsa();
    ret &= test_ecdsa2();
  } else {
    ret &= test_ecc();
    ret &= test_ecdsa();
    ret &= test_ecdsa2();
    ret &= test_ecdsaloop();
  }
  if (ret) {
    printf("OK\n");
  } else {
    printf("Not OK\n");
  }
}
