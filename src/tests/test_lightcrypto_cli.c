//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main() {
  int s = lightcrypto_init("127.0.0.1", "9998", false);

  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK], i;
    key k1, k2;
    head h;

    lightcrypto_transferkey(s, false, &h, &k1);
    k2 = lightcrypto_genkeys(h.g, h.p);
    lightcrypto_transferkey(s, true, &h, &k2);
    lightcrypto_genshare(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    for (i = 0; i < 12; i++) {
      dat[i] = (u64)i; lightcrypto_crypt(dat[i],k1,&cd[i]);
    }
    lightcrypto_transferdata(s, cd, &h, true, 11);
    lightcrypto_end(s);
  }
  // locally generate two keypairs
  srand(time(0));
  lightcrypto_keys();
  printf("OK\n");
  return 0;
}
