//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

#define TEST7_512 "\x08\xec\xb5\x2e\xba\xe1\xf7\x42\x2d\xb6\x2b\xcd\x54\x26\x70"

int main() {
  assert(lh(TEST7_512, LENGTH(TEST7_512), 1, 3, 0x80, 0, 0, "ED8DC78E8B01B69750"
    "053DBB7A0A9EDA0FB9E9D292B1ED715E80A7FE290A4E16664FD913E85854400C5AF05E6DAD"
    "316B7359B43E64F8BEC3C1F237119986BBB6",64) == 1);
  printf("OK\n");
  return 0;
}

