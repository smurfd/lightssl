//                                                                            //
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "../lighthash.h"

int main() {
  uint8_t buf[512] = {0}, str[512] = {0}, next = 0, next2 = 0, s[200] = {0};
  char sss[64], ss[64] = "6a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb";

  memset(buf, 0xA3, 20);
  for (int j = 0; j < 200; j += 20) {next = lh3shake_touch(str, buf, next, true);}
  lh3shake_xof(str, &s);
  for (int i = 0; i < 32; i++) s[i] = str[i];
  for (int j = 0; j < 512; j += 32) {next2 = lh3shake_touch(str, s, next2, false);}
  lh3bit2str(s, sss);
  for (int i = 0; i < 64; i++) {assert(sss[i] == ss[i]);}
  if (*ss) {} // get rid of not used var warning
  printf("OK\n");
  return 0;
}
