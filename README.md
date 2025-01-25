```
             _,.---._    ,--.--------.   _,.---._                  ,-,--.    ,-,--.
   _.-.    ,-.' , -  `. /==/,  -   , -\,-.' , -  `.   .-.,.---.  ,-.'-  _\ ,-.'-  _\  _.-.
 .-,.'|   /==/_,  ,  - \\==\.-.  - ,-./==/_,  ,  - \ /==/  `   \/==/_ ,_.'/==/_ ,_.'.-,.'|
|==|, |  |==|   .=.     |`--`\==\- \ |==|   .=.     |==|-, .=., \==\  \   \==\  \  |==|, |
|==|- |  |==|_ : ;=:  - |     \==\_ \|==|_ : ;=:  - |==|   '='  /\==\ -\   \==\ -\ |==|- |
|==|, |  |==| , '='     |     |==|- ||==| , '='     |==|- ,   .' _\==\ ,\  _\==\ ,\|==|, |
|==|- `-._\==\ -    ,_ /      |==|, | \==\ -    ,_ /|==|_  . ,'./==/\/ _ |/==/\/ _ |==|- `-._
/==/ - , ,/'.='. -   .'       /==/ -/  '.='. -   .' /==/  /\ ,  )==\ - , /\==\ - , /==/ - , ,/
`--`-----'   `--`--''         `--`--`    `--`--''   `--`-`--`--' `--`---'  `--`---'`--`-----'
     auth: smurfd 2024   SSL, sneaky like natures bandit
```
`https://en.wikipedia.org/wiki/Raccoon`

# lotorssl
Do SSL really need to be so hard?

Ciphers: AES<br>
Keys: ECDSA<br>
Crypto: ASN1<br>
Hashing: SHA3-256, SHA3-512<br>

### Compile lotorssl
```bash
make -lotorssl/src
```

### Use lotorssl
See the [tests](https://github.com/smurfd/lotorssl/tree/master/lotorssl/src/tests)

### Compile your project (in the lotorssl/src/example folder)
```bash
gcc -c -o hash.o ../hash.c -fPIC -Wall -pedantic -O3
gcc -c -o keys.o ../keys.c -fPIC -Wall -pedantic -O3
gcc -c -o cryp.o ../cryp.c -fPIC -Wall -pedantic -O3
gcc -c -o ciph.o ../ciph.c -fPIC -Wall -pedantic -O3
gcc example.c -o example hash.o tool.o -Wall -pedantic -O3
./example
rm -f example *.o
```
### Small example (in the lotorssl/src/example folder)
```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../hash.h"

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
[lightcrypto](https://github.com/smurfd/lotorssl/tree/main/lotorssl/src/lightcrypto)
