//                                                                            //
#include <stdint.h>

#ifndef DEFS_H
#define DEFS_H 1

typedef uint64_t u64;
typedef uint8_t  u08;
typedef unsigned char b08;

// SSL
#define SEVENFFF 0x7fffffffffffffff
#define RAND() (rand() & SEVENFFF)
#define M_BUF 1024
#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE "crl.pem"
#define LIGHTTLS_AGAIN -28
#define LIGHTTLS_INTERRUPTED -52
#define LOOP_CHECK(rval, cmd) \
  do {                        \
    rval = cmd;               \
  } while(rval == LIGHTTLS_AGAIN || rval == LIGHTTLS_INTERRUPTED)

// Hash
#define SHFR(x, n) (x >> n)
#define ROTR(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n) ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHFR(x, 7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x, 6))

#define SHA2_UNPACK32(x, str) {      \
  *((str) + 3) = (u08) ((x));        \
  *((str) + 2) = (u08) ((x) >>  8);  \
  *((str) + 1) = (u08) ((x) >> 16);  \
  *((str) + 0) = (u08) ((x) >> 24);  \
}

#define SHA2_UNPACK64(x, str) {      \
  *((str) + 7) = (u08) ((x));        \
  *((str) + 6) = (u08) ((x) >>  8);  \
  *((str) + 5) = (u08) ((x) >> 16);  \
  *((str) + 4) = (u08) ((x) >> 24);  \
  *((str) + 3) = (u08) ((x) >> 32);  \
  *((str) + 2) = (u08) ((x) >> 40);  \
  *((str) + 1) = (u08) ((x) >> 48);  \
  *((str) + 0) = (u08) ((x) >> 56);  \
}

#define SHA2_PACK64(str, x) {  \
  *(x) = ((u64) *((str) + 7))  \
  | ((u64) *((str) + 6) <<  8) \
  | ((u64) *((str) + 5) << 16) \
  | ((u64) *((str) + 4) << 24) \
  | ((u64) *((str) + 3) << 32) \
  | ((u64) *((str) + 2) << 40) \
  | ((u64) *((str) + 1) << 48) \
  | ((u64) *((str) + 0) << 56);\
}

#define RAND64()         \
 ((u64)(RAND()) << 48) ^ \
 ((u64)(RAND()) << 35) ^ \
 ((u64)(RAND()) << 22) ^ \
 ((u64)(RAND()) <<  9) ^ \
 ((u64)(RAND()) >>  4)

#endif
