```
..              ..
oooooo      oooooo
oooooooooooooooooo
oooooooooooooooooo
oooooooooooooooooo
oooo lightSSL oooo
oooooooooooooooooo
oooooooooooooooooo
oooooooooooooooooo
  oooooooooooooo
```
# lightSSL
Do SSL really need to be so hard?

Ciphers: AES<br>
Keys: ECDSA<br>
Crypto: TODO: ASN1<br>
Hashing: SHA2-256 & HMAC, SHA3-256, SHA3-512<br>

### Compile lightssl

```bash
CC=clang meson build
sh ./src/example/gen_cert.sh
CC=clang ninja -C build
CC=clang ninja -C build test -v -d stats -d explain
```
`./build.sh` has those parts in it

### Tests
Test server, in one terminal run
```
./build/test_lightcrypto_srv
```
Test client, in another terminal run
```
./build/test_lightcrypto_cli
```
Test hashing (SHA2-256)
```
./build/test_lighthash
```
Test hashing (SHA3-512)
```
./build/test_lighthash3
```
Test keys (secp384r1)
```
./build/test_lightkeys
```
Test ciphers (AES)
```
./build/test_lightciphers
```
Test crypto (ASN.1) not working yet
```
./build/test_lightcrypto build/ca.key
```
### Use lightssl
See the [tests](https://github.com/smurfd/lightssl/tree/main/src/tests)

### Compile your project (in the src/example folder)
```bash
clang -c -o lighthash.o ../src/lighthash.c -fPIC
clang -c -o lighthash3.o ../src/lighthash3.c -fPIC
clang -c -o lightkeys.o ../src/lightkeys.c -fPIC
clang -c -o lightcrypto.o ../src/lightcrypto.c -fPIC
clang -c -o lightciphers.o ../src/lightciphers.c -fPIC
clang example.c -o example lighthash3.o
./example
rm -f example *.o
```
### Small example (in the src/example folder)
```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../lighthash3.h"

int main() {
  char ss[129] = {0};
  char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2d"
    "cdcc7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20";
  uint8_t *smurfd = (uint8_t*)"smurfd";

  lighthash3_hash_new(smurfd, ss);
  printf("s=%s\n", ss);
  printf("------ // -----\n");
  assert(strcmp(ss, hash) == 0);
}
```

# Very simple Crypto handshake
very simple Crypto handshake in Python
[lightcrypto](https://github.com/smurfd/lightssl/tree/main/src/lightcrypto)
