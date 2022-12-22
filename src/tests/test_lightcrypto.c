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

  int d = 0;
  char s2[257];
  unsigned char s3[257];
  char s[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm";
  unsigned char ss[] = "smurfd and more stuff";

  lightcrypto_decode64(s, strlen(s), &d, s3);
  printf("%s\n", s3);
  lightcrypto_encode64(ss, strlen("smurfd and more stuff"), &d, s2);
  s2[d] = '\0';
  printf("%s\n", s2);
  assert(strcmp(s2, s) == 0);

  printf("OK\n");
  return 0;
}
