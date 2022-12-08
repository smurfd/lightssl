//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lighthash.h"

int main() {
  char* ra = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4F"
    "C5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1";
  char *s = malloc(sha_blk_sz);

  lighthash_hash_new("smurfd", s);
  assert(lighthash_hash_test() == 1);
  assert(strcmp(ra, s) == 0);
  free(s);
  printf("OK\n");
  return 0;
}
