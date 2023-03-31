//                                                                            //
// Very simple handshake
// asn1 - stolen / inspired from https://gitlab.com/mtausig/tiny-asn1
#ifndef LIGHTCRYPTO_H
#define LIGHTCRYPTO_H 1
#include <stdbool.h>
#include <inttypes.h>
#include "lightdefs.h"

typedef struct asn asn;
typedef struct keys key;
typedef struct header head;
typedef struct sockaddr sock;
typedef struct sockaddr_in sock_in;

struct header {u64 len, ver, g, p;};
struct keys {u64 publ, priv, shar;};
struct asn {
  uint8_t type, pos;
  uint32_t len;
  const uint8_t *data;
};
#define ASN1_INTEGER 0x02 // Header byte of the ASN.1 type INTEGER
#define ASN1_BITSTRI 0x03 // Header byte of the ASN.1 type BIT STRING
#define ASN1_OCTSTRI 0x04 // Header byte of the ASN.1 type OCTET STRING
#define ASN1_NULL000 0x05 // Header byte of the ASN.1 type NULL
#define ASN1_OBJIDEN 0x06 // Header byte of the ASN.1 type OBJECT IDENTIFIER
#define ASN1_SEQUENC 0x30 // Header byte of the ASN.1 type SEQUENCE
#define ASN1_SET0000 0x31 // Header byte of the ASN.1 type SET
#define ASN1_UTF8STR 0x12 // Header byte of the ASN.1 type UTF8String
#define ASN1_PRNTSTR 0x19 // Header byte of the ASN.1 type PrintableString
#define ASN1_T61STRI 0x20 // Header byte of the ASN.1 type T61String
#define ASN1_IA5STRI 0x22 // Header byte of the ASN.1 type IA5String
#define ASN1_UTCTIME 0x23 // Header byte of the ASN.1 type UTCTime
#define ASN1_GENTIME 0x24 // Header byte of the ASN.1 type GeneralizedTime

static uint8_t AS1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06};
static uint8_t AS2[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01};
static uint8_t AS3[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};
static uint8_t AS4[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 ,0x2a};
static uint8_t AS5[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02 ,0x30};
int lckeys();
int lclisten(int s, sock *cli);
int lcinit(cc *host, cc *port, bool b);
key lcgenkeys(u64 g, u64 p);

void lcend(int s);
void lccrypt(u64 data, key k, u64 *enc);
void lcgenshare(key *k1, key *k2, u64 p, bool srv);
void lctransferkey(int s, bool snd, head *h, key *k);
void lctransferdata(const int s, void* data, head *h, bool snd, u64 len);

u64 lchandle_cert(char *cert, char d[LEN]);
u64 lchandle_asn(char *cert);

// Keep static functions
// u64 lightcrypto_rand();
// int lightcrypto_getblock();
// void *lightcrypto_handler(void *sdesc);
// void lightcrypto_recvkey(int s, head *h, key *k);
// void lightcrypto_sendkey(int s, head *h, key *k);
// void lasn_printhex(const uint8_t *d, uint32_t len);
// uint32_t lasn_get_len(const uint8_t *data, uint32_t len, uint32_t *off, bool t);
// uint32_t lasn_get_len_enc_len(uint32_t datalen);
// int32_t lasn_enc_int(uint32_t val, uint8_t *enc, uint8_t enclen);
// int32_t lasn_dec_uint(uint8_t *enc, uint8_t enclen, uint32_t *dec);
// int32_t lasn_der_objcnt(const uint8_t *der, uint32_t derlen);
// int32_t lasn_der_enc_len(uint32_t len, uint8_t *enc, uint32_t enclen);
#endif
/*
```
    |                                                     |                    .
 cli|                                                     |srv                 .
    |                                                     |                    .
                                                                               .
     _____________ [1] TCP HANDSHAKE _____________________                     .
                                                                               |
     ----- >>> --- [1.1] syn ------------------- >   ----v                     |
     v---- <   --- [1.2] syn ack --------------- <<< -----        handled by os|
     ----- >>> --- [1.3] ack ------------------- >   -----                     |
                              v                                                |
                                                                               .
     _____________ [2] TLS HANDSHAKE _____________________                     .
                                                                               .
     ----- >>> --- [2.1] client hi ------------- >   ----v                     .
     ----- <   --- [2.1] server hi ------------- <<< -----                     .
     v---- <   --- [2.2] verify server crt ----- <<< -----                     .
     ----- >>> --- [2.3] client crt ------------ >   -----                     .
     ----- >>> --- [2.4] key exchange ---------- >   -----                     .
     ----- >>> --- [2.5] change cipher spec ---- >   -----                     .
     ----- >>> --- [2.6] client finish --------- >   ----v                     .
     ----- <   --- [2.7] change cipher spec ---- <<< -----                     .
     v---- <   --- [2.8] server finished ------- <<< -----                     .
     =-=-= >>> -=- [2.9] encrypted traffic -=-=- <<< -=-=-                     .
                                                                               .
     ...                                                                       .
     ...                                                                       .
     ...                                                                       .
     ...                                                                       .
```
[1] https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp
https://en.wikipedia.org/wiki/Handshaking#TCP_three-way_handshake

[2] https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:online-data-security/xcae6f4a7ff015e7d:secure-internet-protocols/a/transport-layer-security-protocol-tls
https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake

[2.1]
  prot ver : tls 1.3
  cipher suite : TLS_RSA_256_SHA
[2.2]
  prot ver : tls 1.3
  cipher suite : TLS_RSA_256_SHA
  cert : pubkey : 0x123456789abcdef
[2.3]
[2.4]
  cli send pre-master key,
  encrypted with servers public key
  cli calculate shared key from pre-master
  store preshared key locally
[2.5]
[2.6]
  send "finish" encrypted with calculated share key
[2.7]
[2.8]
  server calculate shared key & try to decrypt clients "finish
  if successful, send back "finish" encrypted
[2.9]
  cli send data using symmetric encryption and shared key
*/
