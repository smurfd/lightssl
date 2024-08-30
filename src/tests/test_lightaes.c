#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../lightaes.h"

int main(void) {
  const char *vf = "gcm_test_vectors.bin";
  uint8_t *vd;
  aes_init_keygen_tables();
  if (load_file_into_ram(vf, &vd) < 0) {
    printf("Cant load the test vector file\n");
    exit(0);
  }
  if(verify_gcm(vd)) {
    printf("NIST AES-GCM validation test suite: FAILED!\n");
    free(vd);
    exit(0);
  }
  free(vd);
}
