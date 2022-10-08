//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "lightssl.h"
#include "lightbig/src/lightbig.h"
#include "vsh/vsh.h"
#include "lighthash.h"
#include "test_lightssl.h"

int test_sha() {
  // 11 of 11 SHA tests pass
  for (int i = 0; (i <= TESTCOUNT - 1); ++i) {
    int err = hash(h.t[i].testarray, h.t[i].length,
      h.t[i].repeatcount, h.t[i].nr_extrabits,
      h.t[i].extrabits,0, 0, h.t[i].res_arr, h.hashsize);
    assert(err == 1);
    if (err != 1) return 0;
  }
  return 1;
}

int test_hmac() {
  // 7 of 7 HMAC tests pass
  for (int i = 0; (i <= HMACTESTCOUNT-1); ++i) {
    cc *da = hm[i].dataarray[1] ? hm[i].dataarray[1] : hm[i].dataarray[0];
    int dl = hm[i].datalength[1] ? hm[i].datalength[1] : hm[i].datalength[0];
    cuc* ka = (cuc*)(hm[i].keyarray[1] ? hm[i].keyarray[1] : hm[i].keyarray[0]);
    int kl = hm[i].keylength[1] ? hm[i].keylength[1] : hm[i].keylength[0];
    int err = hash(da, dl, 1, 0, 0, ka, kl, hm[i].res_arr[0], hm[i].res_len[0]);
    assert(err == 1);
    if (err != 1) return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  b08 avail[] = {TLSCIPHER};
  b08 select[] = {TLSCIPHERAVAIL};
  b08 compress = TLSCOMPRESSION;

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
        compress, 13371337);
      cl = lightssl_cli_init("127.0.0.1", "12345");
      lightssl_hs_send_hi(cl, false, hs_cli);
      hs_srv_recv = malloc(sizeof(struct hello));
      lightssl_hs_recv_hi(cl, false, hs_srv_recv);
      lightssl_print_hello(hs_srv_recv);
      lightssl_cli_end(cl);
      free(hs_srv_recv); free(hs_cli);
    } else if (strcmp(argv[1], "big") == 0) {
      int add_t = 5, sub_t = 16, mul_t = 3, div_t = 14, mod_t = 2, hex_t = 1;
      int m_t = add_t + mul_t, s_t = m_t + sub_t, d_t = s_t + div_t;
      int mo_t = d_t + mod_t, nrt = mo_t + hex_t, a_t = add_t;
      char *cc = malloc(MAXSTR);
      bigint_t *ac, *ad, *a1;

      big_init_m(3, &ac, &ad, &a1);
      big_alloc_max_m(3, &ac, &ad, &a1);
      // Sanity checks
      cc = "21739871283971298371298371289371298371298371298371298371293";
      big_set(cc, &ac);
      big_resize(&ac, ac->len, ac->len);
      big_assert(cc, &ac);
      big_end_m(3, &ac, &ad, &a1);

      // Big test suite
      big_init_m(3, &ac, &ad, &a1);
      big_alloc_max_m(2, &ac, &ad);
      for (int j = 0; j < 5; j++) {
        for (int i = 0; i < nrt; i++) {
          big_alloc_max_m(1, &a1);
          big_set("0", &a1);
          big_set(a[i], &ac); big_set(b[i], &ad);

          // Addition tests
          if (i < a_t) {big_add(ac, ad, &a1); big_assert(c[i], &a1);}
          // Multiplication tests
          else if (i < m_t) {big_mul(ac, ad, &a1); big_assert(c[i], &a1);}
          // Subtraction tests
          else if (i < s_t) {big_sub(ac, ad, &a1); big_assert(c[i], &a1);}
          // Division tests
          else if (i < d_t) {big_div(ac, ad, &a1); big_assert(c[i], &a1);}
          // Modulo tests
          else if (i < mo_t) {big_mod(ac, ad, &a1); big_assert(c[i], &a1);}
          // Hex tests
          else if (i < nrt) {
            big_mul(ac, ad, &a1); (*a1).base = HEX; big_assert(c[i], &a1);
          }
        }
      }
      big_end_m(2, &ac, &ad);
      printf("OK\n");
    } else if (strcmp(argv[1], "vsh") == 0) {
      // locally generate two keypairs
      srand(time(0));
      vsh_keys();
    } else if (strcmp(argv[1], "hash") == 0) {
      char* ra = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4F"
        "C5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1";
      char *s = malloc(sha_blk_sz);

      assert(test_sha() == 1);
      assert(test_hmac() == 1);
      hash_new("smurfd", s);
      assert(strcmp(ra, s) == 0);
      free(s);
      printf("OK\n");
    }
  }
}
