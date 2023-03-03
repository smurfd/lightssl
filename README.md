<p align="center">
<img src="./img/open-lock.png" width=256px height=256px title="Free access icons created by JessiGue - Flaticon" alt="https://www.flaticon.com/free-icons/free-access">
</p>

# lightSSL
Do SSL really need to be so hard?

Ciphers: AES<br>
Keys: ECDSA<br>
Crypto: ASN1<br>
Hashing: SHA2-256 & HMAC, SHA3-256, SHA3-512<br>

### Compile lightssl

```bash
rm -rf build
cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -DCMAKE_C_COMPILER=clang
sh ./src/example/gen_cert.sh
make -Cbuild
make -Cbuild test
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
./build/test_hash_sha[0-4]
```
Test hashing (HMAC-256)
```
./build/test_hash_hmac[0-4]
```
Test hashing (SHA3-512)
```
./build/test_hash3
```
Test keys (secp384r1)
```
./build/test_keys
```
Test ciphers (AES)
```
./build/test_ciphers
```
Test crypto (ASN.1)
```
./build/test_crypto build/ca.key build/ca128.csm  #AES 128
./build/test_crypto build/ca.key build/ca256.csm  #AES 256
```
### Use lightssl
See the [tests](https://github.com/smurfd/lightssl/tree/main/src/tests)

### Compile your project (in the src/example folder)
```bash
clang -c -o lighthash.o ../src/lighthash.c -fPIC
clang -c -o lightkeys.o ../src/lightkeys.c -fPIC
clang -c -o lightcrypto.o ../src/lightcrypto.c -fPIC
clang -c -o lightciphers.o ../src/lightciphers.c -fPIC
clang example.c -o example lighthash.o
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
