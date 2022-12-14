//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  cc *da = "Test With Truncation";
  int dl = 20;
  cuc* ka = (cuc*)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
    "\x0c\x0c\x0c\x0c\x0c";
  int kl = 20;
  int err = lighthash_hash(da, dl, 1, 0, 0, ka, kl,
    "415FAD6271580A531D4179BC891D87A6", 16);
  assert(err == 1); if (err != 1) return 0;
  printf("OK\n");
  return 0;
}
