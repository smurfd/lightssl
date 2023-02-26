//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "../lightcrypto.h"

int main(int argc, char **argv) {
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257], data[LEN];
  uint8_t s2[] = "smurfd and more stuff", s3[257], s4[LEN];
  int d = 0;

  if (argc < 2) lcrypto_handle_cert("ca.key", data);
  else lcrypto_handle_cert(argv[1], data);
  lcrypto_decode64(s0, strlen(s0), &d, s3);
  lcrypto_encode64(s2, strlen("smurfd and more stuff"), &d, s1);
  assert(strcmp(s1, s0) == 0);
  lcrypto_decode64((char*)data, strlen((char*)data), &d, s4);

  if (argc < 3) lcrypto_handle_asn_arr("ca.csm");
  else lcrypto_handle_asn_arr(argv[2]);
  printf("OK\n");
  return 0;
}
