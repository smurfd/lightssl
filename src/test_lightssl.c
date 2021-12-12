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
    }
  }
  free(out);
  // Crypt
  lightcrypt_init();

  big_init(&biggy);
  big_init(&biggy2);
  big_init(&res);
  big_init(&solution);;

  big_set(&biggy, "1111111911123123123111112312313131313234423234234223213131564345654345643456543");
  big_set(&biggy2, "9222213222222222222222255555555555555555555555555555555555555555555555555555555555555555222212");

  big_add(&biggy, &biggy2, &res);
  big_print(&res);
  big_set(&solution, "9222213222222223333334166678678678666667867868686868789978789789778768687119901209901198678755");
  assert(strcmp(res->d, solution->d) == 0);

  big_sub(&biggy2, &biggy, &res);
  big_print(&res);
  big_set(&solution, "9222213222222221111110344432432432444443243242424242321132321321332342423991209901209911765669");
  assert(strcmp(res->d, solution->d) == 0);

  big_sub(&biggy, &biggy2, &res);
  big_print(&res);
  big_set(&solution, "-9222213222222221111110344432432432444443243242424242321132321321332342423991209901209911765669");
  assert(strcmp(res->d, solution->d) == 0);

  big_cls(&res);
  big_set(&biggy, "34");
  big_set(&biggy2, "11");
  big_set(&solution, "45");
  big_add(&biggy, &biggy2, &res);
  assert(strcmp(res->d, solution->d) == 0);

  big_cls(&res);
  big_set(&biggy, "11");
  big_set(&biggy2, "34");
  big_set(&solution, "45");
  big_add(&biggy, &biggy2, &res);
  assert(strcmp(res->d, solution->d) == 0);

  big_cls(&res);
  big_set(&biggy, "34");
  big_set(&biggy2, "11");
  big_set(&solution, "23");
  big_sub(&biggy, &biggy2, &res);
  assert(strcmp(res->d, solution->d) == 0);

  big_end(&res);
  big_end(&biggy2);
  big_end(&biggy);

  return 0;
}
