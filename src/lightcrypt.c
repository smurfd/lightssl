//                                                                            //
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "lightcrypt.h"
#include "defs.h"
#include <inttypes.h>
#include <limits.h>
 
void lightcrypt_init() {
  unsigned __int128 big1 = 123456788;
  __uint128_t big2 = 123456788;
  if(big1 == big2)
    printf("crypting stuff\n");
}
