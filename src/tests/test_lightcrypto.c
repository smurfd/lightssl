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
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257];
  u08 s2[] = "smurfd and more stuff", s3[257], s4[LEN];
  char data[LEN];
  int d = 0;

  if (argc != 2) lcrypto_handle_cert("ca.key", data);
  else lcrypto_handle_cert(argv[1], data);
  lcrypto_decode64(s0, strlen(s0), &d, s3);
  lcrypto_encode64(s2, strlen("smurfd and more stuff"), &d, s1);
  assert(strcmp(s1, s0) == 0);
  lcrypto_decode64((char*)data, strlen((char*)data), &d, s4);

  FILE *f = fopen("ca.csm", "r");
  uint32_t fs = 0, fpos = 0;

  if (f == NULL) {printf("file err\n"); exit(0);}
  while (EOF != fgetc(f)) ++fs;
  rewind(f);
  uint8_t *cmsd = malloc(fs);
  if (cmsd == NULL) {printf("malloc err\n"); exit(0);}
  int fr = fgetc(f);
  while (fr != EOF && fpos < fs) {cmsd[fpos++] = (uint8_t)fr; fr = fgetc(f);}
  fclose(f);
  dump_and_parse(cmsd, fs);

  printf("OK\n");
  return 0;
}
