//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightcrypto.h"

int main() {
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257];
  u08 s2[] = "smurfd and more stuff", s3[257], s4[2048], data[2048];
  int d = 0;

  lightcrypto_handle_cert("ca.crt", data);

  lightcrypto_decode64(s0, strlen(s0), &d, s3);
  lightcrypto_encode64(s2, strlen("smurfd and more stuff"), &d, s1);
  assert(strcmp(s1, s0) == 0);
  lightcrypto_decode64((char*)data, strlen((char*)data), &d, s4);
  printf("OK\n");
  return 0;
}
