//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lightssl.h"
#include "lighthash.h"

int main(void) {
  const char* in = "smurfd";
  const char* rh = "555cfc37fc24d4971de9b091ef"\
                   "13401b8c5cb8b5b55804da571f"\
                   "b201cbb4fc5d147ac6f5286564"\
                   "56651606546ca42a1070bdfd79"\
                   "d024f3b97dd1bdac7e70f3d1";
  char* out;
  out = (char*) malloc(100);
  strcpy(out, lh_new(in));
  ls_init();
  if (strcasecmp(out, rh) == 0) {
    printf("hash match!\n");
    printf("rh=%s\n", rh);
  }
  return 0;
}
