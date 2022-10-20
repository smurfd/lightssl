//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "lightssl.h"
#include "lighthash.h"
#include "lighthash3.h"
#include "lightvsh.h"
#include "test_lightssl.h"

// TEST SHA
int test_sha_hmac() {
  // 11 of 11 SHA tests pass
  for (int i = 0; (i <= TESTCOUNT - 1); ++i) {
    int err = hash(h.t[i].testarray, h.t[i].length,
      h.t[i].repeatcount, h.t[i].nr_extrabits,
      h.t[i].extrabits, 0, 0, h.t[i].res_arr, h.hashsize);
    assert(err == 1); if (err != 1) return 0;
  }
  // 7 of 7 HMAC tests pass
  for (int i = 0; (i <= HMACTESTCOUNT-1); ++i) {
    cc *da = hm[i].dataarray[1] ? hm[i].dataarray[1] : hm[i].dataarray[0];
    int dl = hm[i].datalength[1] ? hm[i].datalength[1] : hm[i].datalength[0];
    cuc* ka = (cuc*)(hm[i].keyarray[1] ? hm[i].keyarray[1] : hm[i].keyarray[0]);
    int kl = hm[i].keylength[1] ? hm[i].keylength[1] : hm[i].keylength[0];
    int err = hash(da, dl, 1, 0, 0, ka, kl, hm[i].res_arr[0], hm[i].res_len[0]);
    assert(err == 1); if (err != 1) return 0;
  }
  return 1;
}

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
    } else if (strcmp(argv[1], "hash") == 0) {
      char* ra = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4F"
        "C5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1";
      char *s = malloc(sha_blk_sz);

      hash_new("smurfd", s);
      assert(test_sha_hmac() == 1);
      assert(strcmp(ra, s) == 0);
      free(s);
      printf("OK\n");
    } else if (strcmp(argv[1], "vsh_cli") == 0) {
      int s = vsh_init("127.0.0.1", "9998", false);

      if (s >= 0) {
        u64 dat[BLOCK], cd[BLOCK], i;
        key k1, k2;
        head h;
        h.len = 11;

        vsh_transferkey(s, false, &h, &k1);
        k2 = vsh_genkeys(h.g, h.p);
        vsh_transferkey(s, true, &h, &k2);
        vsh_genshare(&k1, &k2, h.p, false);
        printf("share : 0x%.16llx\n", k1.shar);
        for (i = 0; i < h.len+1; i++) {dat[i] = (u64)i;vsh_crypt(dat[i],k1,&cd[i]);}
        vsh_transferdata(s, cd, true, h.len);
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
    } else if (strcmp(argv[1], "hash3") == 0) {
      char str[256];
      char str1[1601], str2[1601];
      uint64_t Ap[5][5][64];

      str2state("smurfd", Ap);
      print_state(Ap);
      state2str(Ap, str);
      printf("------ --- -----\n");
      printf("str = %s\n", str);

      keccak(str, 7, 128, str);
      printf("------ // -----\n");
      printf("str = %s\n", str);
      printf("------------------------------------------------------------------------\n");


      for (int i = 0; i < 1600; i++) str1[i] = 's';
      str2state(str1, Ap);
      print_state(Ap);
      state2str(Ap, str2);
      printf("str2 = %s\n", str2);
      printf("---------------------------------------------------- TH\n");
      th(Ap, Ap);
      print_state(Ap);
      printf("---------------------------------------------------- P\n");

      p(Ap, Ap);
      print_state(Ap);
      keccak(str1, 17, 128, str2);
      printf("------ // -----\n");
      printf("str = %s\n", str2);
      printf("------------------------------------------------------------------------\n");

    }
  }
}
