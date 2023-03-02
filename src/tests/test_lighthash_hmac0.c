//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  cuc* ka = (cuc*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    "\x0b\x0b\x0b\x0b\x0b";
  cc *da = "\x48\x69\x20\x54\x68\x65\x72\x65";
  int dl = 8, kl = 20, err = lh(da, dl, 1, 0, 0, ka, kl, "87AA7CDEA5EF619D4FF0B"
    "4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E"
    "4BE9D914EEB61F1702E696C203A126854", 64);
  assert(err == 1); if (err != 1) return 0;
  printf("OK\n");
  return 0;
}
