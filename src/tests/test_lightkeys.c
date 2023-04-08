//                                                                                                                    //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../lightkeys.h"
#include "../lighttools.h"
#include "../lightcrypto.h"

int main(void) {
  uint8_t p[256], sig[KB * 2],  pubkey[KB + 1],  sec[KB], privkey[KB], h[KB] = {0};
  u64 k[KB] = {0};

  assert(lrand(h, k));
  assert(keys_make(pubkey, privkey, k));
  assert(keys_secr(pubkey, privkey, sec, k));
  assert(keys_sign(privkey, h, sig, k));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
  bit_unpack(p, (u64*)privkey);
  keys_write("ca-own.key", p, 2);

  if (*sig || *pubkey || *sec || *privkey || *h || *k) {} // get rid of not used var warning
  printf("OK\n");
}
