//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

int main() {
  //cuc* ka = (cuc*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
  //  "\x0b\x0b\x0b\x0b\x0b";
  //cc *da = "\x48\x69\x20\x54\x68\x65\x72\x65";
  //int dl = 8, kl = 20;
  assert(lh("\x48\x69\x20\x54\x68\x65\x72\x65", 8, 1, 0, 0, (cuc*)"\x0b\x0b\x0b"
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "87AA7CDEA5EF619D4F"
    "F0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3"
    "F4E4BE9D914EEB61F1702E696C203A126854", 64) == 1);
  printf("OK\n");
  return 0;
}
