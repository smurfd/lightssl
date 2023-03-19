//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightkeys.h"

int main() {
  u64 sig[KB * 2], h[KB], k[KB], pubkey[KB + 1], privkey[KB], sec[KB];

  prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
  for (int i = 0; i < KB; ++i) {usleep(9);h[i] = prng_next();k[i] = prng_next();}
  usleep(1); assert(lkmake_keys(pubkey, privkey, k));
  usleep(1); assert(lkshar_secr(pubkey, privkey, sec, k));
  usleep(1); assert(lksign(privkey, h, sig, k));
  usleep(1); assert(lkvrfy(pubkey, h, sig));
  usleep(1); assert(!lkvrfy(privkey, h, sig)); // assert failure
  if (*sig || *pubkey || *sec || *privkey) {} // get rid of not used var warning
  printf("OK\n");
  return 0;
}
