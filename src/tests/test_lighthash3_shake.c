//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "../lighthash.h"
#include "../lighttools.h"

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
  printf("OK\n");
}
