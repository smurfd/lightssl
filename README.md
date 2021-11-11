# lightssl
Do SSL need to be so hard?


# Compile lightssl

```bash
meson build
cd build
meson compile
meson test
```
or
```bash
./build.sh
```

# Use lightssl in your project
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lightssl.h"
#include "lighthash.h"

int main(void) {
  char* out;
  const char* in = "smurfd";
  const char* rh = "555cfc37fc24d4971de9b091ef"\
                   "13401b8c5cb8b5b55804da571f"\
                   "b201cbb4fc5d147ac6f5286564"\
                   "56651606546ca42a1070bdfd79"\
                   "d024f3b97dd1bdac7e70f3d1";

  out = (char*) malloc(100);
  strcpy(out, lh_new(in));

  // the hash of rh and the generated one match?
  assert(lh_verify(out, rh));
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
