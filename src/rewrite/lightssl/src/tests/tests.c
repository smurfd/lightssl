#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../ecc.h"

uint8_t test_ecc(void) {
  ecc_sign_gen();
  return 1;
}

int main(int argc, char** argv) {
  uint8_t ret = 1;
  if (argc == 1) { // When run without arguments or in CI
    ret &= test_ecc();
  } else {
    ret &= test_ecc();
  }
  if (ret) {
    printf("OK\n");
  } else {
    printf("Not OK\n");
  }
}
