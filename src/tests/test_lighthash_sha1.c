//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../lightdefs.h"
#include "../lighthash.h"

#define TEST42 "smurfd"

int main() {
  assert(lhash_hash(TEST42, length(TEST42),
    1, 0, 0, 0, 0, "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB"
    "4FC5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1",
    64) == 1);
  printf("OK\n");
  return 0;
}
