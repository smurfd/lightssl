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

  // more randomization use :
  // srand(time(0));
  // for (int i = 0; i < BYTES; i++) {k[i] = RAND64(); h[i] = RAND64();}
  assert(lrand(h, k));
  assert(keys_make(pubkey, privkey, k));
  assert(keys_secr(pubkey, privkey, sec, k));
  if (*sig || *pubkey || *sec || *privkey || *h || *k) {} // get rid of not used var warning
  printf("OK\n");
}
