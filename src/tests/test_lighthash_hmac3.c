//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  assert(lh("Test With Truncation", 20, 1, 0, 0,(cuc*)"\x0c\x0c\x0c\x0c\x0c\x0c"
    "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20,"415FAD62715"
    "80A531D4179BC891D87A6", 16) == 1);
  printf("OK\n");
  return 0;
}
