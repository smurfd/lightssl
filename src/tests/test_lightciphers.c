//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include "../lightdefs.h"
#include "../lightciphers.h"

int main() {
  uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, iv[] = {0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[BBL] = {0}, in[BBL] = {0};

  lpencrypt(plain, key, iv, out, false);
  lpdecrypt(out, key, iv, in, false);
  for (uint64_t i = 0; i < BBL; i++) {assert(plain[i] == in[i]);}

  lpencrypt(plain, key, iv, out, true);
  lpdecrypt(out, key, iv, in, true);
  for (uint64_t i = 0; i < BBL; i++) {assert(plain[i] == in[i]);}
  printf("OK\n");
  return 0;
}
