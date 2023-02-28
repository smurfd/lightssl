//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  cc *da = "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
    "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
    "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
  cuc* ka = (cuc*)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
  int dl = 50, kl = 25, err = lh(da, dl, 1, 0, 0, ka, kl, "B0BA46563745"
    "8C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D67927"
    "5CC5788063A5F19741120C4F2DE2ADEBEB10A298DD", 64);
  assert(err == 1); if (err != 1) return 0;
  printf("OK\n");
  return 0;
}
