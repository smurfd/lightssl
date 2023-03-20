//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

#define TEST "abc"

int main() {
  assert(lh(TEST, LENGTH(TEST), 1, 0, 0, 0, 0, "DDAF35A193617ABACC417349AE204"
    "13112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D442"
    "3643CE80E2A9AC94FA54CA49F", 64) == 1);
  printf("OK\n");
  return 0;
}
