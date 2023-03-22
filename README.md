<p align="center">
<img src="./.github/open-lock.png" width=256px height=256px title="Free access icons created by JessiGue - Flaticon" alt="https://www.flaticon.com/free-icons/free-access">
</p>

# lightSSL
Do SSL really need to be so hard?

Ciphers: AES<br>
Keys: ECDSA<br>
Crypto: ASN1<br>
Hashing: SHA3-256, SHA3-512<br>

### Compile lightSSL

```bash
rm -rf build
cmake -DCMAKE_BUILD_TYPE=Debug -Bbuild/debug -DCMAKE_C_COMPILER=clang
sh ./src/scripts/gen_cert.sh
make -Cbuild/debug
make -Cbuild/debug test
```
`./scr/scripts/build.sh` has those parts in it. Use the Debug type to have
asserts working.

### Tests
Test server, in one terminal run
```
./build/debug/debug_test_crypto_srv
```
Test client, in another terminal run
```
./build/debug/debug_test_crypto_cli
```
Test hashing (SHA3-512)
```
./build/debug/debug_test_hash3
```
Test hashing Shake
```
./build/debug/debug_test_hash3_shake
```
Test keys (secp384r1)
```
./build/debug/debug_test_keys
```
Test ciphers (AES)
```
./build/debug/debug_test_ciphers
```
Test crypto (ASN.1)
```
./build/debug/debug_test_crypto build/debug/ca.key build/debug/ca128.cms  #AES 128
./build/debug/debug_test_crypto build/debug/ca.key build/debug/ca256.cms  #AES 256
```
### Use lightSSL
See the [tests](https://github.com/smurfd/lightssl/tree/master/src/tests)

### Compile your project (in the src/example folder)
```bash
clang -c -o lighthash.o ../lighthash.c -fPIC -Wall -pedantic -O3
clang -c -o lightkeys.o ../lightkeys.c -fPIC -Wall -pedantic -O3
clang -c -o lightcrypto.o ../lightcrypto.c -fPIC -Wall -pedantic -O3
clang -c -o lightciphers.o ../lightciphers.c -fPIC -Wall -pedantic -O3
clang example.c -o example lighthash.o -Wall -pedantic -O3
./example
rm -f example *.o
```
### Small example (in the src/example folder)
```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../lighthash.h"

int main() {
  char hash[] = "5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc"
    "7d61e73d4f2c51051e45d26215f9f7729b8986549e169dcee3280bed61cda25f20",ss[129];
  uint8_t *smurfd = (uint8_t*)"smurfd";

  lh3new(smurfd, ss);
  printf("s=%s\n", ss);
  printf("------ // -----\n");
  assert(strcmp(ss, hash) == 0);
}
```

# Very simple Crypto handshake
very simple Crypto handshake in Python
[lightcrypto](https://github.com/smurfd/lightssl/tree/main/src/lightcrypto)
