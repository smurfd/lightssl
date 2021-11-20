//                                                                            //
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "lightcrypt.h"
#include <inttypes.h>
#include <limits.h>
void lightcrypt_init() {
  struct lightcurve c;
  unsigned __int128 big1 = 123456788;
  __uint128_t big2 = 123456788;
  strcpy(c.name, "secp256k1");
  // BIG problems
  //c.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fULL;
  c.a = 0;
  c.b = 7;
  //c.g[0] = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ULL;
  //c.g[1] = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ULL;
  c.h = 1;
  if(big1 == big2)
    printf("crypting stuff\n");
}
