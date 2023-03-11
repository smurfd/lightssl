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
  assert(lkmake_keys(pubkey, privkey));
  assert(lkshar_secr(pubkey, privkey, sec));
  assert(lksign(privkey, h, sig));
  assert(lkvrfy(pubkey, h, sig));
  assert(!lkvrfy(privkey, h, sig)); // Assume failure
  if (*sec || *sig || *privkey || *pubkey || *h) { } // clear no use warn
  printf("OK\n");
  return 0;
}
