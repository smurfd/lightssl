//                                                                            //
#include <stdint.h>

#ifndef DEFS_H
#define DEFS_H 1

typedef unsigned char byte8_t;

// SSL
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

#define SHA2_UNPACK32(x, str) {          \
  *((str) + 3) = (uint8_t) ((x));        \
  *((str) + 2) = (uint8_t) ((x) >>  8);  \
  *((str) + 1) = (uint8_t) ((x) >> 16);  \
  *((str) + 0) = (uint8_t) ((x) >> 24);  \
}
#define SHA2_UNPACK64(x, str) {          \
  *((str) + 7) = (uint8_t) ((x));        \
  *((str) + 6) = (uint8_t) ((x) >>  8);  \
  *((str) + 5) = (uint8_t) ((x) >> 16);  \
  *((str) + 4) = (uint8_t) ((x) >> 24);  \
  *((str) + 3) = (uint8_t) ((x) >> 32);  \
  *((str) + 2) = (uint8_t) ((x) >> 40);  \
  *((str) + 1) = (uint8_t) ((x) >> 48);  \
  *((str) + 0) = (uint8_t) ((x) >> 56);  \
}
#define SHA2_PACK64(str, x) {            \
  *(x) = ((uint64_t) *((str) + 7))       \
       | ((uint64_t) *((str) + 6) <<  8) \
       | ((uint64_t) *((str) + 5) << 16) \
       | ((uint64_t) *((str) + 4) << 24) \
       | ((uint64_t) *((str) + 3) << 32) \
       | ((uint64_t) *((str) + 2) << 40) \
       | ((uint64_t) *((str) + 1) << 48) \
       | ((uint64_t) *((str) + 0) << 56);\
}

#endif
