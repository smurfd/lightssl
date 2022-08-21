#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "vsh.h"

// gcc vsh_srv.c vsh.c -o srv
// ./srv (in one terminal window)

//
// server main
int main() {
  struct sockaddr *cli = NULL;
  int s = vsh_init("127.0.0.1", "9998", true);
  vsh_listen(s, cli);
  vsh_end(s);
}