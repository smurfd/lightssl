//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "lightbig.h"
#include "lightssl.h"
#include "lighthash.h"
#include "lightcrypt.h"

int main(int argc, char **argv) {
  uint64_t c;
  char *out = NULL;
  b08 avail[] = {TLSCIPHER};
  b08 select[] = {TLSCIPHERAVAIL};
  b08 compress = TLSCOMPRESSION;
  bigint_t *biggy, *biggy2, *res, *solution;

  const char* in = "smurfd";
  const char* rh = "555cfc37fc24d4971de9b091ef"\
                   "13401b8c5cb8b5b55804da571f"\
                   "b201cbb4fc5d147ac6f5286564"\
                   "56651606546ca42a1070bdfd79"\
                   "d024f3b97dd1bdac7e70f3d1";

  out = (char*) malloc(100);
  strcpy(out, lighthash_new(in));

  // the hash of rh and the generated one match?
  assert(lighthash_verify(out, rh));
  printf("The hashes match!\nRealHash:  %s\nGenerated: %s\n", rh, out);

  if (argc == 2 && argv) {
    if (strcmp(argv[1], "server") == 0) {
      struct sockaddr *cli = NULL;
      int s = lightssl_srv_init("127.0.0.1", "12345");
      lightssl_srv_listen(s, cli);
    } else if (strcmp(argv[1], "client") == 0) {
      struct hello *hs_cli;
      struct hello *hs_srv_recv;
      hs_cli = (struct hello*) malloc(sizeof(struct hello));
      lightssl_hs_set_hello(hs_cli, false, TLSVERSION, 1337, avail, select, compress, 13371337);
      int cl = lightssl_cli_init("127.0.0.1", "12345");
      lightssl_hs_send_hi(cl, false, hs_cli);
      hs_srv_recv = (struct hello*) malloc(sizeof(struct hello));
      lightssl_hs_recv_hi(cl, false, hs_srv_recv);
      lightssl_print_hello(hs_srv_recv);
      lightssl_cli_end(cl);
      free(hs_srv_recv);
      free(hs_cli);
    } else if (strcmp(argv[1], "big") == 0) {
      bigint_t *ac, *ad, *a1;
      big_set("21739871283971298371298371289371298371298371298371298371293", &ac);
	    assert(strcmp("21739871283971298371298371289371298371298371298371298371293", big_get(ac)) == 0);

      big_set("000123000", &ac);
	    assert(strcmp("123000", big_get(ac)) == 0);

      big_set("000", &ac);
	    assert(strcmp("0", big_get(ac)) == 0);
      big_set("", &ac);
	    assert(strcmp("0", big_get(ac)) == 0);

      big_init(&a1);
      big_set("11111111111111111111111111111111111111111111111111111111111000", &ac);
      big_set("33333333333333333333333333333333333333333333333333333333333789", &ad);
      big_add(ac, ad, &a1);
	    assert(strcmp("44444444444444444444444444444444444444444444444444444444444789", big_get(a1)) == 0);

      big_init(&a1);
      big_set("512", &ac);
      big_set("512", &ad);
      big_add(ac, ad, &a1);
	    assert(strcmp("1024", big_get(a1)) == 0);

      big_init(&a1);
      big_set("2048", &ac);
      big_set("8", &ad);
      big_mul(ac, ad, &a1);
      assert(strcmp("16384", big_get(a1)) == 0);

      big_init(&a1);
      big_set("1024", &ac);
      big_set("16", &ad);
      big_mul(ac, ad, &a1);
	    assert(strcmp("16384", big_get(a1)) == 0);

      big_init(&a1);
      big_set("1111111911123123123111112312313131313234423234234223213131564345654345643456543", &ac);
      big_set("9222213222222222222222255555555555555555555555555555555555555555555555555555555555555555222212", &ad);
      big_mul(ac, ad, &a1);
      assert(strcmp(
        "1024691095812826869391663147282954873019529886520580529524817192884099563"\
        "0206654276591188107806120144189700371037426747541472468434747817753423563"\
        "299873235240318870130333116", big_get(a1)) == 0);

      big_init(&a1);
      big_set("9222213222222222222222255555555555555555555555555555555555555555555555555555555555555555222212", &ac);
      big_set("1111111911123123123111112312313131313234423234234223213131564345654345643456543", &ad);
      big_add(ac, ad, &a1);
      assert(strcmp("9222213222222223333334166678678678666667867868686868789978789789778768687119901209901198678755",
        big_get(a1)) == 0);

      big_init(&a1);
      big_set("600", &ac);
      big_set("22", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("578", big_get(a1)) == 0);

      big_init(&a1);
      big_set("578", &ac);
      big_set("22", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("556", big_get(a1)) == 0);

      big_init(&a1);
      big_set("268", &ac);
      big_set("122", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("146", big_get(a1)) == 0);

      big_init(&a1);
      big_set("600", &ac);
      big_set("22", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("27", big_get(a1)) == 0);

      big_init(&a1);
      big_set("10", &ac);
      big_set("3", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("3", big_get(a1)) == 0);

      big_init(&a1);
      big_set("10", &ac);
      big_set("3", &ad);
      big_mod(ac, ad, &a1);
      assert(strcmp("1", big_get(a1)) == 0);

      big_set("100", &ac);
      big_set("63", &ad);
      big_mod(ac, ad, &a1);
      assert(strcmp("37", big_get(a1)) == 0);

      printf("OK!\n");
    } else if (strcmp(argv[1], "crypt") == 0) {
      lightcrypt_init();
    }
  }
  free(out);
}
