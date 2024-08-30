//                                                                                                                    //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include "../lightkeys.h"
#include "../lighttools.h"
#include "../lightcrypto.h"

//
// urandom generate u64
u64 u64rnd(void) {
  u64 f7 = 0x7fffffffffffffff;
  int r[5], f = open("/dev/urandom", O_RDONLY);
  read(f, &r, sizeof r);
  close(f);
  return (r[0] & f7) << 48 ^ (r[1] & f7) << 35 ^ (r[2] & f7) << 22 ^ (r[3] & f7) << 9 ^ (r[4] & f7) >> 4;
}

int main(void) {
  uint8_t sig[BYTES * 2],  pubkey[BYTES + 1],  sec[BYTES], privkey[BYTES], h[BYTES] = {0};
  u64 k[BYTES] = {0};
  // more randomization use :
  // srand(time(0));
  // for (int i = 0; i < BYTES; i++) {k[i] = RAND64(); h[i] = RAND64();}
  assert(lrand(h, k));

  //for (uint8_t i = 0; i < BYTES; i++) {
    //h[i] = (uint8_t)u64rnd();
    //k[i] = u64rnd();
  //}

  for (int i = 0; i < BYTES; ++i)
    printf("%d %llu\n", h[i], k[i]);

  assert(keys_make(pubkey, privkey, k));
  assert(keys_secr(pubkey, privkey, sec, k));
  assert(keys_sign(privkey, h, sig, k));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
  if (*sig || *pubkey || *sec || *privkey || *h || *k) {} // get rid of not used var warning
  printf("OK\n");
}
