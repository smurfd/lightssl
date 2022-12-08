//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lighthash3.h"

int main() {
  char s[128] = {0};
  char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2d"
    "cdcc7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20";
  uint8_t *smurfd = (uint8_t*)"smurfd";

  lighthash3_hash_new(smurfd, s);
  assert(strcmp(s, hash) == 0);
  printf("OK\n");
  return 0;
}