#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "vsh.h"

// gcc vsh_cli.c vsh.c -o cli
// ./cli (in one terminal window)

//
// client main
int main() {
  int c = vsh_init("127.0.0.1", "9998", false);
  char *cc = malloc(100);
  vsh_send(c, "this is a long string doodz");
  vsh_recv(c, cc);

  printf("recv: %s\n", cc);
  vsh_end(c);
  free(cc);

  srand(time(0));
  keypair();
}
