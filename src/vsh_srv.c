//                                                                            //
// Very simple handshake
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "vsh.h"

//
// Server main
int main() {
  int s = vsh_init("127.0.0.1", "9998", true);
  sock *cli = NULL;

  vsh_listen(s, cli);
  vsh_end(s);
}
