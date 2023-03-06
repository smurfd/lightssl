//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  cc *da = "Test With Truncation";
  cuc* ka = (cuc*)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
    "\x0c\x0c\x0c\x0c\x0c";
  int kl = 20, dl = 20, err = lh(da, dl, 1, 0, 0, ka, kl,"415FAD6271580A531D417"
    "9BC891D87A6", 16);
  assert(err == 1);
  printf("OK\n");
  return 0;
}
