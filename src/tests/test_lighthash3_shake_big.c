//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "../lighthash.h"
#include "../lighttools.h"

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
  printf("OK\n");
}
