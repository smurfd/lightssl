# lightssl
Do SSL need to be so hard?


# Compile lightssl

````bash
meson build
cd build
meson compile
meson test
```
or
````bash
./build.sh
```

# Use lightssl in your project
```c
#include <stdio.h>
#include <liblightssl.h>

int main() {
  lightssl_init();
  lightssl_update();
  lightssl_finalize();
  return 0;
}
```
