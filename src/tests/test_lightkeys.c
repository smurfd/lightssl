//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../lightkeys.h"
#include "../lighttools.h"
#include "../lightcrypto.h"


int main(void) {
  u64 sig[KB * 2], h[KB], k[KB], pubkey[KB + 1], privkey[KB], sec[KB];
  uint8_t key[KB], key2[257];
  int d;

  assert(lkrand(h, k));
  assert(lkmake_keys(pubkey, privkey, k));
  assert(lkshar_secr(pubkey, privkey, sec, k));
  assert(lksign(privkey, h, sig, k));
  assert(lkvrfy(pubkey, h, sig));
  assert(!lkvrfy(privkey, h, sig)); // assert failure
  for (int i = 0; i < KB; i++) {key[i] = (uint8_t)privkey[i];}
  lcencode64(key, 128, &d, key2);
  printf("%s\n", (char*)key2);

  lkcreate_cert("ca-own.crt", key, 1);
  lkcreate_cert("ca-own.key", key2, 2);
  lkcreate_cert("ca-own.cms", privkey, 3);

  if (*sig || *pubkey || *sec || *privkey || *h || *k) {} // get rid of not used var warning
  printf("OK\n");
  return 0;
}
