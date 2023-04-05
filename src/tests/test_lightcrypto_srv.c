//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../lightcrypto.h"

int main(void) {
  int s = crypto_init("127.0.0.1", "9998", true);
  sock *cli = NULL;

  if (srv_listen(s, cli) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  crypto_end(s);
  printf("OK\n");
}
