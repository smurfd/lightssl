//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  cc *da = "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
    "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
    "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
  int dl = 50;
  cuc* ka = (cuc*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "\xaa\xaa\xaa\xaa\xaa";
  int kl = 20;
  int err = lighthash_hash(da, dl, 1, 0, 0, ka, kl, "FA73B0089D56A284EFB0F0756C"
    "890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946"
    "A337BEE8942674278859E13292FB", 64);
  assert(err == 1); if (err != 1) return 0;
  printf("OK\n");
  return 0;
}
