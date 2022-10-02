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
int checkmatch(const unsigned char *hashvalue,
  const char *hexstr, int hashsize) {
  int i;
  for (i = 0; i < hashsize; ++i) {
    if (*hexstr++ != hexdigits[(hashvalue[i] >> 4) & 0xF])
      return 0;
    if (*hexstr++ != hexdigits[hashvalue[i] & 0xF]) return 0;
  }
  return 1;
}

/*
 * Print the string, converting all characters to hex "## ".
 */
void printxstr(const char *str, int len) {
  for (;len-- > 0; str++) {
    printf("%c%c", hexdigits[(*str >> 4) & 0xF], hexdigits[*str & 0xF]);
  }
}

/*
 * Print the results and PASS/FAIL.
 */
void printResult(uint8_t *Message_Digest, int hashsize,
    const char *hashname, const char *testtype, const char *testname,
    const char *resultarray, int printResults, int printPassFail) {
  int i, k;
    printf("Hash : ");
    for (i = 0; i < hashsize; ++i) {
      putchar(hexdigits[(Message_Digest[i] >> 4) & 0xF]);
      putchar(hexdigits[Message_Digest[i] & 0xF]);
    }
    putchar('\n');
    printf("Match: ");
    for (i = 0, k = 0; i < hashsize; i++, k += 2) {
      putchar(resultarray[k]);
      putchar(resultarray[k+1]);
    }
    putchar('\n');
    int ret = checkmatch(Message_Digest, resultarray, hashsize);
    if ((printPassFail == PRINTPASSFAIL) || !ret)
      printf("%s %s %s: %s\n", hashname, testtype, testname,
        ret ? "PASSED" : "FAILED");
}

/*
 * Exercise a hash series of functions.  The input is the testarray,
 * repeated repeatcount times, followed by the extrabits.  If the
 * result is known, it is in resultarray in uppercase hex.
 */
int hash(int testno, int loopno, int hashno,
  const char *testarray, int length, long repeatcount,
  int numberExtrabits, int extrabits, const unsigned char *keyarray,
  int keylen, const unsigned char *info, int infolen, int okmlen,
  const char *resultarray, int hashsize, int printResults,
  int printPassFail) {
  SHA512Context sha;
  HMACContext hmac;
  int err, i;
  uint8_t Message_Digest_Buf[SHA512HashSize];
  uint8_t *Message_Digest = Message_Digest_Buf;
  char buf[20];

  if (info) Message_Digest = malloc(okmlen);
  memset(&sha, '\343', sizeof(sha)); // force bad data into struct
  memset(&hmac, '\343', sizeof(hmac));

  err = keyarray ? hmacReset(&hmac,
                             keyarray, keylen) :
                   SHA512Reset((SHA512Context*)&sha);
  if (err != shaSuccess) {return err;}

  for (i = 0; i < repeatcount; ++i) {
    err = keyarray ? hmacInput(&hmac, (const uint8_t *) testarray, length) :
          SHA512Input((SHA512Context*)&sha, (const uint8_t *) testarray, length);

    if (err != shaSuccess) {return err;}
  }

  if (numberExtrabits > 0) {
    err = keyarray ? hmacFinalBits(&hmac, (uint8_t)extrabits, numberExtrabits) :
    SHA512FinalBits((SHA512Context*)&sha, (uint8_t)extrabits, numberExtrabits);
    if (err != shaSuccess) {return err;}
  }

  err = keyarray ? hmacResult(&hmac, Message_Digest) :
        SHA512Result((SHA512Context*)&sha, Message_Digest);

  if (err != shaSuccess) {return err;}

  sprintf(buf, "%d", testno+1);
  printResult(Message_Digest, hashsize, "SHA512",
    keyarray ? "hmac standard test" : "sha standard test", buf,
    resultarray, printResults, printPassFail);
  return err;
}

int main(int argc, char **argv) {
  int i, err;
  int loopno, loopnohigh = 1;
  int hashno, hashnolow = 0, hashnohigh = HASHCOUNT - 1;
  int testno, testnolow = 0, testnohigh;
  int ntestnohigh = 0;
  int printResults = PRINTTEXT;
  int printPassFail = 1;
  int checkErrors = 0;
  char *hashstr = 0;
  int hashlen = 0;
  const char *resultstr = 0;
  int runHmacTests = 0;
  int runHkdfTests = 0;
  char *hmacKey = 0;
  int hmaclen = 0;
  char *info = 0;
  int infolen = 0, okmlen = 0;
  const char *hashfilename = 0;
  const char *hashFilename = 0;
  int extrabits = 0, numberExtrabits = 0;
  int strIsHex = 0;

  testnohigh = (ntestnohigh != 0) ? ntestnohigh: runHmacTests ? (HMACTESTCOUNT-1) :
    (TESTCOUNT-1);

  for (hashno = hashnolow; hashno <= hashnohigh; ++hashno) {
    if (printResults == PRINTTEXT) err = shaSuccess;

    for (loopno = 1; (loopno <= loopnohigh) && (err == shaSuccess); ++loopno) {
      if (hashstr)
        err = hash(0, loopno, hashno, hashstr, hashlen, 1,
          numberExtrabits, extrabits, (const unsigned char *)hmacKey,
          hmaclen, (const uint8_t *) info, infolen, okmlen, resultstr,
          hashes[hashno].hashsize, printResults, printPassFail);

      else {
        for (testno = testnolow; (testno <= testnohigh) && (err == shaSuccess); ++testno) {
          if (runHmacTests) {
            err = hash(testno, loopno, hashno,
                       hmachashes[testno].dataarray[hashno],
                       hmachashes[testno].datalength[hashno],
                       1, 0, 0,
                       (const unsigned char *)(
                        hmachashes[testno].keyarray[hashno]),
                       hmachashes[testno].keylength[hashno],
                       0, 0, 0,
                       hmachashes[testno].resultarray[hashno],
                       SHA512HashSize,
                       printResults, printPassFail);
          } else {
            err = hash(testno, loopno, hashno,
                       hashes[hashno].tests[testno].testarray,
                       hashes[hashno].tests[testno].length,
                       hashes[hashno].tests[testno].repeatcount,
                       hashes[hashno].tests[testno].numberExtrabits,
                       hashes[hashno].tests[testno].extrabits,
                       0, 0, 0, 0, 0,
                       hashes[hashno].tests[testno].resultarray,
                       hashes[hashno].hashsize,
                       printResults, printPassFail);
          }
        }
      }
    }
  }

  return 0;
}
