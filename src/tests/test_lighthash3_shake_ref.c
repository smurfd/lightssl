//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "../lighthash.h"
#include "../lighttools.h"

int main(void) {
  uint8_t out_gold1[512], in_gold1[1024], out_gold2[512], in_gold2[1024];
  uint8_t res[] = {0xf6, 0x49, 0x68, 0x85, 0x8b, 0x5c, 0xd8, 0xa6, 0x4f, 0xfd, 0xd9, 0x2e, 0x8c, 0x72, 0xda, 0x03, 0x87,
       0xc5, 0x68, 0x9b, 0x56, 0x2e, 0x96, 0x28, 0x86, 0x04, 0xdf, 0x95, 0x31, 0x5f, 0xee, 0xfa, 0x5a, 0xe9, 0xf0, 0x59,
       0x6b, 0x0b, 0x3d, 0x47, 0xcd, 0x61, 0xac, 0x67, 0x6a, 0xd1, 0xfb, 0x20, 0xcf, 0x3d, 0x92, 0xab, 0x2b, 0x68, 0xda,
       0xa4, 0x89, 0x31, 0xcc, 0x58, 0xd6, 0xd7, 0x23, 0xc7};
  char s[] = "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3";

  for (int i = 0; i < 20; i++) {in_gold1[i] = s[i]; in_gold2[i] = s[i];}
  shake256(out_gold1, 64, in_gold1, 20);
  shake256(out_gold2, 64, in_gold2, 20);

  for (int i = 0; i < 64; i++) {printf("%02x %02x %02x\n", out_gold1[i], out_gold2[i], res[i]);}
  for (int i = 0; i < 64; i++) {assert(out_gold1[i] == res[i]); assert(out_gold2[i] == res[i]);}
  if ((*res)) {} // get rid of not used var warning
  printf("OK\n");
}
