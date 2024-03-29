//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../lightcrypto.h"
#include "../lighttools.h"

int main(int argc, char **argv) {
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257], data[LEN], c[8192];
  uint8_t s2[] = "smurfd and more stuff", s3[257], s4[LEN];

  if (argc == 1) {
    crypto_handle_cert(data, "build/debug/ca.key");
    crypto_handle_asn(c, "build/debug/ca256.cms");
  } else if (argc == 3) {
    crypto_handle_cert(data, argv[1]);
    crypto_handle_asn(c, argv[2]);
    base64dec(s4, (char*)data, strlen((char*)data));
  }
  base64dec(s3, s0, strlen(s0));
  base64enc(s1, s2, strlen("smurfd and more stuff"));
  assert(strcmp(s1, s0) == 0);
  printf("OK\n");
}
