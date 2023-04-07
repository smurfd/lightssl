//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main(void) {
  int s = crypto_init("127.0.0.1", "9998", false);

  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK];
    key k1, k2;
    head h;

    crypto_transfer_key(s, false, &h, &k1);
    k2 = crypto_gen_keys(h.g, h.p);
    crypto_transfer_key(s, true, &h, &k2);
    crypto_gen_share(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    for (u64 i = 0; i < 12; i++) {
      dat[i] = (u64)i; cryption(dat[i], k1, &cd[i]);
    }
    crypto_transfer_data(s, cd, &h, true, 11);
    crypto_end(s);
  }
  // locally generate two keypairs
  srand(time(0));
  crypto_gen_keys_local();
  printf("OK\n");
}
