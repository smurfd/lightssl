//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "lighthash.h"
#include "lighthash3.h"
#include "lightcrypto.h"
#include "lightkeys.h"
#include "lightciphers.h"

void print_usage() {
  printf("Usage: ./build/test_lightssl <test>\n");
  printf("  <test> crypto_cli | crypto_srv | hash | hash3 | keys\n");
}

int main(int argc, char **argv) {
  if (argc != 2) {
    print_usage();
    exit(0);
  }
  if (strcmp(argv[1], "crypto_cli") == 0) {
    int s = lightcrypto_init("127.0.0.1", "9998", false);

    if (s >= 0) {
      u64 dat[BLOCK], cd[BLOCK], i;
      key k1, k2;
      head h;

      lightcrypto_transferkey(s, false, &h, &k1);
      k2 = lightcrypto_genkeys(h.g, h.p);
      lightcrypto_transferkey(s, true, &h, &k2);
      lightcrypto_genshare(&k1, &k2, h.p, false);
      printf("share : 0x%.16llx\n", k1.shar);
      for (i = 0; i < 12; i++) {
        dat[i] = (u64)i; lightcrypto_crypt(dat[i],k1,&cd[i]);
      }
      lightcrypto_transferdata(s, cd, &h, true, 11);
      lightcrypto_end(s);
    }
    // locally generate two keypairs
    srand(time(0));
    lightcrypto_keys();
  } else if (strcmp(argv[1], "crypto_srv") == 0) {
    int s = lightcrypto_init("127.0.0.1", "9998", true);
    sock *cli = NULL;

    if (lightcrypto_listen(s, cli) < 0) {printf("Can't Thread\n"); exit(0);}
    lightcrypto_end(s);
  } else if (strcmp(argv[1], "hash") == 0) {
    char* ra = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4F"
      "C5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1";
    char *s = malloc(sha_blk_sz);

    lighthash_hash_new("smurfd", s);
    assert(lighthash_hash_test() == 1);
    assert(strcmp(ra, s) == 0);
    free(s);
    printf("OK\n");
  } else if (strcmp(argv[1], "hash3") == 0) {
    char s[128] = {0};
    char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2d"
      "cdcc7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20";
    uint8_t *smurfd = (uint8_t*)"smurfd";

    lighthash3_hash_new(smurfd, s);
    assert(strcmp(s, hash) == 0);
    printf("OK\n");
  } else if (strcmp(argv[1], "keys") == 0) {
    u64 sig[KB * 2], h[KB * 2], pubkey[KB + 1], privkey[KB], sec[KB];

    prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
    for (int i = 0; i < KB; ++i) {usleep(10); h[i] = prng_next();}

    usleep(1); assert(keys_make_keys(pubkey, privkey));
    usleep(1); assert(keys_shar_secr(pubkey, privkey, sec));
    usleep(1); assert(keys_sign(privkey, h, sig));
    usleep(1); assert(keys_vrfy(pubkey, h, sig));
    printf("OK\n");
  } else if (strcmp(argv[1], "ciphers") == 0) {
    ui BBLE = 16 * sizeof(u08);
    u08 out[32] = {0}, in[32] = {0};

    u08 plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u08 iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u08 key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    lightciphers_cip();
    lightciphers_encrypt(plain, BBL, key, iv, out);
    lightciphers_decrypt(out, BBL, key, iv, in);
    for (int i =0; i < BBL; i++) {
      printf("%x %x\n", plain[i], in[i]);
      if (plain[i] == in[i]) {
        printf("SWEET\n");
      } else {
        printf("NOOOO\n");
        break;
      }
    }
    printf("OK\n");
  } else {print_usage();}
}
