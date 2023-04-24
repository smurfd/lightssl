//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "../lighthash.h"
#include "../lighttools.h"

int test_shake256(void) {
  uint8_t out_gold1[512], in_gold1[1024], out_gold2[512], in_gold2[1024];
  uint8_t res[] = {0x75, 0x74, 0x60, 0x89, 0x24, 0x0d, 0x9e, 0x39, 0xff, 0xf1, 0xb4, 0xba, 0x58, 0x13, 0x0a, 0xf5, 0xb9,
       0x74, 0x4f, 0x41, 0x2a, 0x9d, 0xff, 0x73, 0x84, 0x70, 0xd1, 0x24, 0x72, 0x53, 0xd3, 0x2c, 0xe7, 0xfe, 0x5a, 0xef,
       0x0d, 0x43, 0xda, 0x15, 0x5f, 0x29, 0x08, 0x58, 0xa4, 0x2e, 0xa0, 0x41, 0xd3, 0x9a, 0x6b, 0xfd, 0x04, 0x21, 0xd4,
       0x49, 0x8e, 0xa4, 0x95, 0xbd, 0x41, 0x3a, 0x9f, 0x58};
  char s[130] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et\
 dolore magna aliqua. Ut eni";

  for (int i = 0; i < 130; i++) {in_gold1[i] = s[i]; in_gold2[i] = s[i];}
  shake256(out_gold1, 64, in_gold1, 130);
  shake256(out_gold2, 64, in_gold2, 130);

  for (int i = 0; i < 64; i++) {printf("%02x %02x %02x\n", out_gold1[i], out_gold2[i], res[i]);}

  for (int i = 0; i < 64; i++) {assert(out_gold1[i] == res[i]); assert(out_gold2[i] == res[i]);}
  if ((*res)) {}

  return 0;
}

int main(void) {
  uint8_t str[512] = {0}, s[200] = {0}, next = 0, next2 = 0;
  char sss[64], ss[66] = "0xa6c9b436fbe5c2f4a4682ce1bc3447681b0b73f823c3bffd3a3828ec3692c2e6";
  uint8_t *plain = (uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt\
 ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip e\
x ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pa\
riatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

  for (int i = 0; i < 200; i += 20)
    hash_shake_touch(str, plain, &next, true);

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
