//                                                                                                                    //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../lightkeys.h"
#include "../lighttools.h"
#include "../lightcrypto.h"

int main(void) {
  uint8_t pubkey[BYTES + 1] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  keys_write("ca-own.key", privkey, 2);
}
