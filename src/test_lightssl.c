//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "lightssl.h"
#include "lightvsh.h"
#include "lighthash.h"
#include "lighthash3.h"

int main(int argc, char **argv) {
  b08 avail[] = {TLSCIPHER}, select[] = {TLSCIPHERAVAIL}, cmpr = TLSCOMPRESSION;

  if (argc == 2 && argv) {
    if (strcmp(argv[1], "server") == 0) {
      struct sockaddr *cli = NULL;
      int s = lightssl_srv_init("127.0.0.1", "12345");

      lightssl_srv_listen(s, cli);
    } else if (strcmp(argv[1], "client") == 0) {
      struct hello *hs_cli, *hs_srv_recv;
      int cl;

      hs_cli = malloc(sizeof(struct hello));
      lightssl_hs_set_hello(hs_cli, false, TLSVERSION, 1337, avail, select,
        cmpr, 13371337);
      cl = lightssl_cli_init("127.0.0.1", "12345");
      lightssl_hs_send_hi(cl, false, hs_cli);
      hs_srv_recv = malloc(sizeof(struct hello));
      lightssl_hs_recv_hi(cl, false, hs_srv_recv);
      lightssl_print_hello(hs_srv_recv);
      lightssl_cli_end(cl);
      free(hs_srv_recv); free(hs_cli);
    } else if (strcmp(argv[1], "vsh_cli") == 0) {
      int s = vsh_init("127.0.0.1", "9998", false);

      if (s >= 0) {
        u64 dat[BLOCK], cd[BLOCK], i;
        key k1, k2;
        head h;

        vsh_transferkey(s, false, &h, &k1);
        k2 = vsh_genkeys(h.g, h.p);
        vsh_transferkey(s, true, &h, &k2);
        vsh_genshare(&k1, &k2, h.p, false);
        printf("share : 0x%.16llx\n", k1.shar);
        for (i = 0; i < 12; i++) {dat[i] = (u64)i;vsh_crypt(dat[i],k1,&cd[i]);}
        vsh_transferdata(s, cd, &h, true, 11);
        vsh_end(s);
      }
      // locally generate two keypairs
      srand(time(0));
      vsh_keys();
    } else if (strcmp(argv[1], "vsh_srv") == 0) {
      int s = vsh_init("127.0.0.1", "9998", true);
      sock *cli = NULL;

      if (vsh_listen(s, cli) < 0) {printf("Can't create Thread\n"); exit(0);}
      vsh_end(s);
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
    }
  }
}
