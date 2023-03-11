//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../lightkeys.h"

int main() {
    u64 sig[KB * 2], h[KB * 2], pubkey[KB + 1], privkey[KB], sec[KB];

    prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
    for (int i = 0; i < KB; ++i) {usleep(10); h[i] = prng_next();}

    usleep(1); assert(keys_make_keys(pubkey, privkey));
    usleep(1); assert(keys_shar_secr(pubkey, privkey, sec));
    usleep(1); assert(keys_sign(privkey, h, sig));
    usleep(1); assert(keys_vrfy(pubkey, h, sig));
    printf("OK\n");
  return 0;
}
