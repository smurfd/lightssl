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
  char *cc = malloc(vsh_getblock());
  int c = vsh_init("127.0.0.1", "9998", false);

  if (c >= 0) {
    key k1, k2;
    head h;

    vsh_transferkey(c, false, false, &h, &k1);
    k2 = vsh_genkeys(h.g, h.p);
    vsh_transferkey(c, true, false, &h, &k2);
    vsh_genshare(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    vsh_end(c);
  }
  free(cc);
  srand(time(0));
  vsh_keys();
}
