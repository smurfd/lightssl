//                                                                                                                    //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lighthash.h"

int main(void) {
  uint8_t *plain = (uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt\
 ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip e\
x ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pa\
riatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
  char s[256];

  hash_new(s, plain);
  assert(strcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0f09") == 0);
  assert(strcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0fff") != 0); // Assume failure
  printf("OK\n");
}
