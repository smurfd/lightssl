```
 @@@@@@  @@@  @@@  @@@@@@ @@@@@@@  @@@  @@@@@@@  @@@@@@  @@@@@@@ @@@  @@@  @@@@@@ @@@@@@@ @@@@@@@@ @@@@@@@@
@@!  @@@ @@!  @@@ !@@     @@!  @@@ @@! !@@      @@!  @@@   @@!   @@!  @@@ !@@     !@@          @@!      @@!
@!@!@!@! @!@  !@!  !@@!!  @!@@!@!  !!@ !@!      @!@!@!@!   @!!   @!@  !@!  !@@!!  !!@@!!      @!!      @!!
!!:  !!! !!:  !!!     !:! !!:      !!: :!!      !!:  !!!   !!:   !!:  !!!     !:!     !:!  .!!:     .!!:
 :   : :  :.:: :  ::.: :   :       :    :: :: :  :   : :    :     :.:: :  ::.: :  :: : :  : :      : :
     auth: smurfd 2024   SSL, sneaky like natures bandit
```
`https://en.wikipedia.org/wiki/Raccoon`

# auspicatus577
Do SSL really need to be so hard?

Ciphers: AES<br>
Keys: ECDSA<br>
Crypto: ASN1<br>
Hashing: SHA3-256, SHA3-512<br>

### Compile auspicatus577
```bash
make -Causpicatus577/src
```

### Use auspicatus577
See the [tests](https://github.com/smurfd/auspicatus577/tree/master/auspicatus577/src/tests)

### Compile your project (in the auspicatus577/src/example folder)
```bash
clang -c -o lighttools.o ../lighttools.c -fPIC -Wall -pedantic -O3
clang -c -o lighthash.o ../lighthash.c -fPIC -Wall -pedantic -O3
clang -c -o lightkeys.o ../lightkeys.c -fPIC -Wall -pedantic -O3
clang -c -o lightcrypto.o ../lightcrypto.c -fPIC -Wall -pedantic -O3
clang -c -o lightciphers.o ../lightciphers.c -fPIC -Wall -pedantic -O3
clang example.c -o example lighthash.o lighttools.o -Wall -pedantic -O3
./example
rm -f example *.o
```
### Small example (in the auspicatus577/src/example folder)
```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../lighthash.h"

int main(void) {
  uint8_t *smurfd = (uint8_t*)"smurfd";
  char s[256] = {0}, res[] = "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f\
9f7729b8986549e169dcee3280bed61cda25f20";
  hash_new(s, smurfd);
  assert(strcmp(s, res) == 0);
  assert(strcmp(s + 1, res) != 0); // Assume failure
  printf("OK\n");
}
```

# Very simple Crypto handshake
very simple Crypto handshake in Python
[lightcrypto](https://github.com/smurfd/auspicatus577/tree/main/auspicatus577/src/lightcrypto)
