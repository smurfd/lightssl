//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../lightcrypto.h"
#include "../lighttools.h"

int main(int argc, char **argv) {
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257], data[LEN];
  uint8_t s2[] = "smurfd and more stuff", s3[257], s4[LEN];
  int d = 0;

  if (argc < 2) {
    lchandle_cert("ca.key", data);
    assert(lchandle_asn("ca128.cms") == 0); assert(lchandle_asn("ca256.cms") == 0);
  } else {lchandle_cert(argv[1], data); assert(lchandle_asn(argv[2]) == 0);}
  lcdecode64(s0, strlen(s0), &d, s3);
  lcencode64(s2, strlen("smurfd and more stuff"), &d, s1);
  assert(strcmp(s1, s0) == 0);
  lcdecode64((char*)data, strlen((char*)data), &d, s4);
  printf("OK\n");
}
