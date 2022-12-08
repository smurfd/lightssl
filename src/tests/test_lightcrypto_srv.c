//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main() {
  int s = lightcrypto_init("127.0.0.1", "9998", true);
  sock *cli = NULL;

  if (lightcrypto_listen(s, cli) < 0) {printf("Can't Thread\n"); exit(0);}
  lightcrypto_end(s);
  printf("OK\n");
  return 0;
}
