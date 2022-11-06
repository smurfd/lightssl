
# lightSSL
Do SSL really need to be so hard?

Ciphers: TODO: Blowfish / AES<br>
Keys: TODO: ECDH / ECDSA<br>
Crypto: TODO: ASN1<br>
Hashing: SHA2-256 & HMAC, SHA3-256, SHA3-512<br>

### Compile lightssl

```bash
CC=clang meson build
CC=clang ninja -C build
CC=clang ninja -C build test -v -d stats -d explain
```
`./build.sh` has those parts in it

### Run client and server
In one terminal run
```
./build/test_lightssl crypto_srv
```
In another terminal run
```
./build/test_lightssl crypto_cli
```
Test hashing (SHA2-256)
```
./build/test_lightssl hash
```
Test hashing (SHA3-512)
```
./build/test_lightssl hash3
```

### Use lightssl
See the [tests](https://github.com/smurfd/lightssl/raw/main/src/test_lightssl.c)

### Compile your project (in the example folder)
```bash
rm -rf build && ./build.sh
cd example
cp ../src/*.h .
cp ../build/*.a .
./build_your_project.sh
./example
```
### Small example (in the example folder)
```c
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "lighthash3.h"

int main() {
 char *s = malloc(128);
 char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2d"
    "cdcc7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20";
  uint8_t *smurfd = (uint8_t*)"smurfd";

  keccak(smurfd, s);
  printf("s=%s\n", s);
  printf("------ // -----\n");
  assert(strcmp(s, hash) == 0);
  free(s);
}
```

# Very simple Crypto handshake
very simple Crypto handshake in Python
[lightcrypto](https://github.com/smurfd/lightssl/tree/main/src/lightcrypto)
