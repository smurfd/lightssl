//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightkeys.h"

int main() {
  uint64_t sig[KB * 2], h[KB * 2], pubkey[KB + 1], privkey[KB], sec[KB];

  lkrnd_init((uint64_t)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
  for (int i = 0; i < KB; ++i) {usleep(10); h[i] = lkrnd_next();}

  usleep(1); assert(lkmake_keys(pubkey, privkey));
  usleep(1); assert(lkshar_secr(pubkey, privkey, sec));
  usleep(1); assert(lksign(privkey, h, sig));
  usleep(1); assert(lkvrfy(pubkey, h, sig));
  usleep(1); assert(!lkvrfy(privkey, h, sig)); // Assume failure
  if (*sec || *sig || *privkey || *pubkey || *h) { } // clear no use warn
  printf("OK\n");
  return 0;
}
