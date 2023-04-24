//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "../lighthash.h"
#include "../lighttools.h"

int test_shake256(void) {
  uint8_t out_gold1[512], in_gold1[1024], out_gold2[512], in_gold2[1024];
  uint8_t res[] = {0x0d, 0xcf, 0xbc, 0x11, 0xbd, 0xd2, 0x43, 0x82, 0x4b, 0x31, 0xe5, 0x13, 0x5b, 0x8f, 0x83, 0xfa, 0x1c,
       0x11, 0x8d, 0xd7, 0x6a, 0xc0, 0xea, 0xaf, 0xee, 0x19, 0x10, 0x17, 0x0b, 0xa5, 0x61, 0x89, 0xa5, 0x8d, 0x21, 0x2a,
       0xa2, 0xb4, 0x2d, 0xfe, 0xbd, 0x1b, 0x8c, 0xdd, 0x08, 0xa4, 0xc4, 0xd5, 0xae, 0xcb, 0xfa, 0x0c, 0x33, 0x60, 0x0f,
       0x39, 0x78, 0x8b, 0x75, 0x81, 0xb5, 0xbb, 0x4f, 0x42};
  char s[] = "smurfd";

  for (int i = 0; i < 6; i++) {in_gold1[i] = s[i]; in_gold2[i] = s[i];}
  shake256(out_gold1, 64, in_gold1, 6);
  shake256(out_gold2, 64, in_gold2, 6);

  for (int i = 0; i < 64; i++) {printf("%02x %02x %02x\n", out_gold1[i], out_gold2[i], res[i]);}

  for (int i = 0; i < 64; i++) {assert(out_gold1[i] == res[i]); assert(out_gold2[i] == res[i]);}
  if ((*res)) {}

  return 0;
}

int main(void) {
  uint8_t str[512] = {0}, s[200] = {0}, next = 0, next2 = 0;
  char sss[66]={0}, ss[66] = "0xc59a34d4356567e98fcacfd18c42771ad450704784bf24cd0884ca992e931423";
  uint8_t *smurfd = (uint8_t*)"smurfd\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  for (int i = 0; i < 200; i += 20)
    hash_shake_touch(str, smurfd, &next, true);

  hash_shake_xof(str);
  memcpy(s, str, 32 * sizeof(uint8_t));

  for (int i = 0; i < 512; i += 32)
    hash_shake_touch(str, s, &next2, false);

  bit_hex_str(sss, s, 64);
  for (int i = 0; i < 66; i++) {
    assert(sss[i] == ss[i]);
    assert(sss[i] != (ss[i] + 1));
  }
  if (*ss) {} // get rid of not used var warning

  test_shake256();
  printf("OK\n");
}
