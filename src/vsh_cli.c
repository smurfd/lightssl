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
    vsh_send(c, "this is a long string doodz");
    vsh_recv(c, cc);

    printf("recv: %s\n", cc);
    vsh_end(c);
  }
  free(cc);
  srand(time(0));
  assert(vsh_keys() == 1);
}
