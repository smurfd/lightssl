//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main() {
  int s = lcrypto_init("127.0.0.1", "9998", false);

  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK];
    key k1, k2;
    head h;

    lcrypto_transferkey(s, false, &h, &k1);
    k2 = lcrypto_genkeys(h.g, h.p);
    lcrypto_transferkey(s, true, &h, &k2);
    lcrypto_genshare(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    for (u64 i = 0; i < 12; i++) {
      dat[i] = (u64)i; lcrypto_crypt(dat[i],k1,&cd[i]);
    }
    lcrypto_transferdata(s, cd, &h, true, 11);
    lcrypto_end(s);
  }
  // locally generate two keypairs
  srand(time(0));
  lcrypto_keys();
  printf("OK\n");
  return 0;
}
