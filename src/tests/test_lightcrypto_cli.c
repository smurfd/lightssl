//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main(void) {
  int s = lcinit("127.0.0.1", "9998", false);

  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK];
    key k1, k2;
    head h;

    lctransferkey(s, false, &h, &k1);
    k2 = lcgenkeys(h.g, h.p);
    lctransferkey(s, true, &h, &k2);
    lcgenshare(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    for (u64 i = 0; i < 12; i++) {
      dat[i] = (u64)i; lccrypt(dat[i], k1, &cd[i]);
    }
    lctransferdata(s, cd, &h, true, 11);
    lcend(s);
  }
  // locally generate two keypairs
  srand(time(0));
  lckeys();
  printf("OK\n");
  return 0;
}
