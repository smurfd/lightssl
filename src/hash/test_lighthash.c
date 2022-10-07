//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <stdio.h>
#include <assert.h>
#include "lighthash.h"
#include "test_lighthash.h"

int test_sha() {
  // 11 of 11 SHA tests pass
  for (int i = 0; (i <= TESTCOUNT - 1); ++i) {
    int err = hash(h.t[i].testarray, h.t[i].length,
      h.t[i].repeatcount, h.t[i].nr_extrabits,
      h.t[i].extrabits,0, 0, h.t[i].res_arr, h.hashsize);
    assert(err == 1);
    if (err != 1) return 0;
  }
  return 1;
}

int test_hmac() {
  // 7 of 7 HMAC tests pass
  for (int i = 0; (i <= HMACTESTCOUNT-1); ++i) {
    cc *da = hm[i].dataarray[1] ? hm[i].dataarray[1] : hm[i].dataarray[0];
    int dl = hm[i].datalength[1] ? hm[i].datalength[1] : hm[i].datalength[0];
    cuc* ka = (cuc*)(hm[i].keyarray[1] ? hm[i].keyarray[1] : hm[i].keyarray[0]);
    int kl = hm[i].keylength[1] ? hm[i].keylength[1] : hm[i].keylength[0];
    int err = hash(da, dl, 1, 0, 0, ka, kl, hm[i].res_arr[0], hm[i].res_len[0]);
    assert(err == 1);
    if (err != 1) return 0;
  }
  return 1;
}

int main() {
  if (test_sha() == 1) printf("OK\n");
  if (test_hmac() == 1) printf("OK\n");
  return 0;
}