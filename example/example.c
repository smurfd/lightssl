#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "lighthash3.h"

int main() {
 char *s = malloc(128);
 char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2d"
    "cdcc7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20";
  uint8_t *smurfd = (uint8_t*)"smurfd";

  keccak(smurfd, s);
  printf("s=%s\n", s);
  printf("------ // -----\n");
  assert(strcmp(s, hash) == 0);
  free(s);
}
