//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../lightcrypto.h"

int main(void) {
  int s = lcinit("127.0.0.1", "9998", true);
  sock *cli = NULL;

  if (lclisten(s, cli) < 0) {printf("Can't Thread\n"); exit(0);}
  lcend(s);
  printf("OK\n");
}
