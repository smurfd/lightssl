# lightssl
Do SSL really need to be so hard?

# Dependency
C is not good with big numbers. Using [gmp](https://gmplib.org) for that

# Compile lightssl

```bash
meson build
cd build
meson compile
meson test
```
`./build.sh` has those parts in it

# Run client and server
In one terminal run
```
./build/test_lightssl server
```
In another teerminal run
```
./build/test_lightssl client
```

# Use lightssl in your project
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "lightssl.h"
#include "lighthash.h"
#include "lightcrypt.h"

int main(int argc, char **argv) {
  char *out = NULL;
  b08 avail[] = {TLSCIPHER};
  b08 select[] = {TLSCIPHERAVAIL};
  b08 compress = TLSCOMPRESSION;

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
      lightssl_hs_set_hello(hs_cli, false, TLSVERSION, 1337, avail, select, compre
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
  return 0;
}
```
# Compile your project
```bash
cp src/*.h ../newproj/src
cp build/*.a ../newproj/src
cp build_your_project.sh ../newproj/src
cd ../newproj/src
./build_your_project.sh
```
