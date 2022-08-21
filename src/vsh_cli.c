#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "vsh.h"

// gcc vsh_cli.c vsh.c -o cli
// ./cli (in one terminal window)

//
// client main
int main() {
  char *cc = malloc(BLOCK);
  int c = vsh_init("127.0.0.1", "9998", false);
  srand(time(0));

  if (c >= 0) {
    vsh_send(c, "this is a long string doodz");
    vsh_recv(c, cc);

    printf("recv: %s\n", cc);
    vsh_end(c);
  }
  free(cc);

  vsh_keys();
}
