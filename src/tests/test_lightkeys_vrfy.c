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
  uint8_t sig[BYTES * 2],  pubkey[BYTES + 1],  sec[BYTES], privkey[BYTES], h[BYTES] = {0};
  u64 k[BYTES] = {0};
  assert(lrand(h, k));
  assert(keys_make(pubkey, privkey, k));
  assert(keys_secr(pubkey, privkey, sec, k));
  assert(keys_sign(privkey, h, sig, k));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
  if (*sig || *pubkey || *sec || *privkey || *h || *k) {} // get rid of not used var warning
}
