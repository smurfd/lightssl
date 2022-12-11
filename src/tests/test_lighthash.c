//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../defs.h"
//#include "../lightdefs.h"
#include "../lighthash.h"
#include "lighthash_testdata.h"
//
// HMAC & SHA Test suite runner
int lighthash_hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs) {
  u08 msg_dig[sha_hsh_sz], err;
  ctxh hmac;
  ctxs sha;

  if (k) {err = hmac_reset(&hmac, k, kl);}
  else {err = sha_reset(&sha);}
  if (err != sha_ok) {return err;}

  for (int i = 0; i < r; ++i) {
    if (k) {err = hmac_input(&hmac, (cu8 *)ta, l);}
    else {err = sha_input(&sha, (cu8 *)ta, l);}
    if (err != sha_ok) {return err;}
  }

  if (neb > 0) {
    if (k) {err = hmac_final(&hmac, (u08)eb, neb);}
    else {err = sha_final(&sha, (u08)eb, neb);}
    if (err != sha_ok) {return err;}
  }

  if (k) {err = hmac_result(&hmac, msg_dig);}
  else {err = sha_result(&sha, msg_dig);}
  if (err != sha_ok) {return err;}
  return sha_match_to_str(msg_dig, ra, hs, NULL);
}

int lighthash_hash_test() {
  // 11 of 11 SHA tests pass
  for (int i = 0; (i <= TESTCOUNT - 1); ++i) {
    int err = lighthash_hash(h.t[i].testarray, h.t[i].length,
      h.t[i].repeatcount, h.t[i].nr_extrabits,
      h.t[i].extrabits, 0, 0, h.t[i].res_arr, h.hashsize);
    assert(err == 1); if (err != 1) return 0;
  }
  // 7 of 7 HMAC tests pass
  for (int i = 0; (i <= HMACTESTCOUNT-1); ++i) {
    cc *da = hm[i].dataarray[1] ? hm[i].dataarray[1] : hm[i].dataarray[0];
    int dl = hm[i].datalength[1] ? hm[i].datalength[1] : hm[i].datalength[0];
    cuc* ka = (cuc*)(hm[i].keyarray[1] ? hm[i].keyarray[1] : hm[i].keyarray[0]);
    int kl = hm[i].keylength[1] ? hm[i].keylength[1] : hm[i].keylength[0];
    int err = lighthash_hash(da, dl, 1, 0, 0, ka, kl, hm[i].res_arr[0], hm[i].res_len[0]);
    assert(err == 1); if (err != 1) return 0;
  }
  return 1;
}

int main() {
  char* ra = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4F"
    "C5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1";
  char* rb = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4F"
    "C5D147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7EFFFFFF";
  char s[sha_blk_sz + 1];

  lighthash_hash_new("smurfd", s);
  assert(lighthash_hash_test() == 1);
  assert(strcmp(ra, s) == 0);
  assert(strcmp(rb, s) != 0); // Assume failure
  printf("OK\n");
  return 0;
}
