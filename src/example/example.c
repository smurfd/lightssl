#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../lighthash.h"

int main() {
  char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc"
    "7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20",ss[129];
  uint8_t *smurfd = (uint8_t*)"smurfd";

  lh3new(smurfd, ss);
  printf("s=%s\n", ss);
  printf("------ // -----\n");
  assert(strcmp(ss, hash) == 0);
}
