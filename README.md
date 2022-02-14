# lightssl
Do SSL really need to be so hard?

### Compile lightssl

```bash
meson build
cd build
meson compile
meson test
```
`./build.sh` has those parts in it

### Run client and server
In one terminal run
```
./build/test_lightssl server
```
In another teerminal run
```
./build/test_lightssl client
```
Test Big number math
```
./build/test_lightssl big
```
Test cryptography
```
./build/test_lightssl crypt
```
Test hashing
```
./build/test_lightssl hash
```


### Use lightssl in your project
```c
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
  const char* in = "smurfd";
  const char* rh = "555cfc37fc24d4971de9b091ef13401b8c5cb8b5b55804da571fb201c"\
      "bb4fc5d147ac6f528656456651606546ca42a1070bdfd79d024f3b97dd1bdac7e70f3d1";

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
      int cl;

      hs_cli = (struct hello*) malloc(sizeof(struct hello));
      lightssl_hs_set_hello(hs_cli, false, TLSVERSION, 1337, avail,
          select, compress, 13371337);
      cl = lightssl_cli_init("127.0.0.1", "12345");
      lightssl_hs_send_hi(cl, false, hs_cli);
      hs_srv_recv = (struct hello*) malloc(sizeof(struct hello));
      lightssl_hs_recv_hi(cl, false, hs_srv_recv);
      lightssl_print_hello(hs_srv_recv);
      lightssl_cli_end(cl);
      free(hs_srv_recv);
      free(hs_cli);
    } else if (strcmp(argv[1], "big") == 0) {
      bigint_t *ac, *ad, *a1;
      big_set("21739871283971298371298371289371298371298371298371298"\
          "371293", &ac);
	  assert(strcmp("21739871283971298371298371289371298371298371298"\
          "371298371293", big_get(ac)) == 0);

      big_set("000123000", &ac);
	  assert(strcmp("123000", big_get(ac)) == 0);

      big_set("000", &ac);
	  assert(strcmp("0", big_get(ac)) == 0);
      big_set("", &ac);
	  assert(strcmp("0", big_get(ac)) == 0);

      big_init(&a1);
      big_set("11111111111111111111111111111111111111111111111111111"\
          "111111000", &ac);
      big_set("33333333333333333333333333333333333333333333333333333"\
          "333333789", &ad);
      big_add(ac, ad, &a1);
	  assert(strcmp("44444444444444444444444444444444444444444444444"\
          "444444444444789", big_get(a1)) == 0);

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
      big_set("11111119111231231231111123123131313132344232342342232"\
          "13131564345654345643456543", &ac);
      big_set("92222132222222222222222555555555555555555555555555555"\
          "55555555555555555555555555555555555222212", &ad);
      big_mul(ac, ad, &a1);
      assert(strcmp(
          "102469109581282686939166314728295487301952988652058052952"\
          "481719288409956302066542765911881078061201441897003710374"\
          "267475414724684347478177534235632998732352403188701303331"\
          "16", big_get(a1)) == 0);

      big_init(&a1);
      big_set("92222132222222222222222555555555555555555555555555555"\
          "55555555555555555555555555555555555222212", &ac);
      big_set("11111119111231231231111123123131313132344232342342232"\
          "13131564345654345643456543", &ad);
      big_add(ac, ad, &a1);
      assert(strcmp("92222132222222233333341666786786786666678678686"\
          "86868789978789789778768687119901209901198678755",
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

      big_init(&a1);
      big_set("10000", &ac);
      big_set("3", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("3333", big_get(a1)) == 0);

      big_init(&a1);
      big_set("97783168081539600805195362086833632135046007441292693"\
          "645370130530607805355644243164623752694677180743783866721"\
          "110324463092282923155195553231284779451989130560241037445"\
          "839460215375857597677332187354870290870376682705989540881"\
          "6333758974", &ac);
      big_set("11579208923731619542357098500868790785326998466564056"\
          "4039457584007908834671663", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("84447192140330707113963255284567556577780406282"\
          "036509216346035040359412893309935964430990836169086995487"\
          "13958186537951429186564022152176310381675487752022988",
          big_get(a1)) == 0);

      printf("OK!\n");
    } else if (strcmp(argv[1], "crypt") == 0) {
      lightcrypt_init();
    }
  }
  free(out);
}
```
### Compile your project
```bash
cp src/*.h ../newproj/src
cp build/*.a ../newproj/src
cp build_your_project.sh ../newproj/src
cd ../newproj/src
./build_your_project.sh
```
