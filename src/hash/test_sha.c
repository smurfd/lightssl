//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "sha.h"
#include "test_const.h"

//
// Check the hash value against the expected string, expressed in hex
int checkmatch(cuc *hashvalue, cc *hexstr, int hashsize) {
  for (int i = 0; i < hashsize; ++i) {
    if (*hexstr++ != hexdigits[(hashvalue[i] >> 4) & 0xF]) return 0;
    if (*hexstr++ != hexdigits[hashvalue[i] & 0xF]) return 0;
  }
  return 1;
}

void printResult(uint8_t *md, int hashsize, cc *resultarray) {
  printf("Hash : ");
  for (int i = 0; i < hashsize; ++i) {
    printf("%c%c", hexdigits[(md[i] >> 4) & 0xF], hexdigits[md[i] & 0xF]);
  }
  printf("\nMatch: ");
  for (int i = 0; i < hashsize * 2; i += 2) {
    printf("%c%c", resultarray[i], resultarray[i + 1]);
  }
  if (checkmatch(md, resultarray, hashsize) == 1)
    printf(" PASSED\n"); else printf(" FAILED\n");
}

int hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs) {
  uint8_t Message_Digest_Buf[SHA512HashSize];
  uint8_t *Message_Digest = Message_Digest_Buf;
  SHA512Context sha;
  HMACContext hmac;
  int err;

  memset(&sha, '\343', sizeof(sha)); // force bad data into struct
  memset(&hmac, '\343', sizeof(hmac));

  if (k) {err = hmacReset(&hmac, k, kl);}
  else {err = SHA512Reset((SHA512Context*)&sha);}
  if (err != shaSuccess) {return err;}

  for (int i = 0; i < r; ++i) {
    if (k) {err = hmacInput(&hmac, (const uint8_t *)ta, l);}
    else {err = SHA512Input((SHA512Context*)&sha, (const uint8_t *)ta, l);}
    if (err != shaSuccess) {return err;}
  }

  if (neb > 0) {
    if (k) {hmacFinalBits(&hmac, (uint8_t)eb, neb);}
    else {SHA512FinalBits((SHA512Context*)&sha, (uint8_t)eb, neb);}
    if (err != shaSuccess) {return err;}
  }

  if (k) {err = hmacResult(&hmac, Message_Digest);}
  else {err = SHA512Result((SHA512Context*)&sha, Message_Digest);}
  if (err != shaSuccess) {return err;}
  printResult(Message_Digest, hs, ra);
  return err;
}

int main() {
  printf("SHA\n"); // 11 of 11 tests pass
  for (int i = 0; (i <= TESTCOUNT - 1); ++i) {
    hash(h[0].t[i].testarray, h[0].t[i].length,
      h[0].t[i].repeatcount, h[0].t[i].numberExtrabits,
      h[0].t[i].extrabits,0, 0, h[0].t[i].resultarray, h[0].hashsize);
  }
  printf("HMAC\n"); // 7 of 7 tests pass
  for (int i = 0; (i <= HMACTESTCOUNT-1); ++i) {
    cc *da = hm[i].dataarray[1] ? hm[i].dataarray[1] : hm[i].dataarray[0];
    int dl = hm[i].datalength[1] ? hm[i].datalength[1] : hm[i].datalength[0];
    cuc* ka = (cuc*)(hm[i].keyarray[1] ? hm[i].keyarray[1] : hm[i].keyarray[0]);
    int kl = hm[i].keylength[1] ? hm[i].keylength[1] : hm[i].keylength[0];
    hash(da, dl, 1, 0, 0, ka, kl, hm[i].resultarray[0], hm[i].resultlength[0]);
  }
  return 0;
}
