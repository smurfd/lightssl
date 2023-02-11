//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

#define TEST1 "abc"

int main() {
  assert(lhash_hash(TEST1, length(TEST1),
    1, 0, 0, 0, 0, "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B5"
    "5D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
    64) == 1);
  printf("OK\n");
  return 0;
}
