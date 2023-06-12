#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../lighthash.h"

int main(void) {
  uint8_t *smurfd = (uint8_t*)"smurfd";
  char s[256] = {0}, res[] = "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f\
9f7729b8986549e169dcee3280bed61cda25f20";

  hash_new(s, smurfd);
  assert(strcmp(s, res) == 0);
  assert(strcmp(s + 1, res) != 0); // Assume failure
  printf("OK\n");
}
