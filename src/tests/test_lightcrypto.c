//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main() {
  lightcrypto_handle_cert("ca.crt");
  printf("OK\n");
  return 0;
}
