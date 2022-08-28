//                                                                            //
// Very simple handshake
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include "vsh.h"

//
// Client main
int main() {
  int i, s = vsh_init("127.0.0.1", "9998", false);

  if (s >= 0) {
    u64 dat[12], cd[12];
    key k1, k2;
    head h;

    vsh_transferkey(s, false, &h, &k1);
    k2 = vsh_genkeys(h.g, h.p);
    vsh_transferkey(s, true, &h, &k2);
    vsh_genshare(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    for (i = 0; i < 12; i++) {dat[i] = (u64)i;vsh_crypt(dat[i], k1, &cd[i]);}
    vsh_transferdata(s, cd, true, 11);
    vsh_end(s);
  }

  // locally generate two keypairs
  srand(time(0));
  vsh_keys();
}
