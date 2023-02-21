//                                                                            //
// Very simple handshake
#ifndef LIGHTCRYPTO_H
#define LIGHTCRYPTO_H 1
#include <stdbool.h>
#include <inttypes.h>
#include "lightdefs.h"

typedef struct keys key;
typedef struct header head;
typedef struct sockaddr sock;
typedef struct sockaddr_in sock_in;

struct header {u64 len, ver, g, p;};
struct keys {u64 publ, priv, shar;};
#define LEN 4096
static char enc[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'};
static uint8_t AS1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06};
static uint8_t AS2[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01};
static uint8_t AS3[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};

key lcrypto_genkeys(u64 g, u64 p);
int lcrypto_keys();
int lcrypto_init(cc *host, cc *port, bool b);
int lcrypto_listen(int s, sock *cli);

void lcrypto_end(int s);
void lcrypto_crypt(u64 data, key k, u64 *enc);
void lcrypto_genshare(key *k1, key *k2, u64 p, bool srv);
void lcrypto_transferkey(int s, bool snd, head *h, key *k);
void lcrypto_transferdata(const int s, void* data, head *h, bool snd, u64 len);

u64 lcrypto_handle_cert(char *cert, char d[LEN]);
u64 lcrypto_handle_asn(char *cert);

void lcrypto_encode64(cuc *data, int inl, int *ol, char ed[*ol]);
void lcrypto_decode64(cc *data, int inl, int *ol, u08 dd[*ol]);
u32 utf8decode(u32 c);
u32 utf8encode(u32 cp);

// asn1
// stolen / inspired from https://gitlab.com/mtausig/tiny-asn1
typedef struct asn_tree asn_tree;

struct asn_tree {
  uint8_t type;
  uint32_t len;
  const uint8_t *data;

  asn_tree *parent;
  asn_tree *child;
  asn_tree *next;
  asn_tree *prev;
};

/** Header byte of the ASN.1 type INTEGER */
#define ASN1_TYPE_INTEGER 0x02
/** Header byte of the ASN.1 type BIT STRING */
#define ASN1_TYPE_BIT_STRING 0x03
/** Header byte of the ASN.1 type OCTET STRING */
#define ASN1_TYPE_OCTET_STRING 0x04
/** Header byte of the ASN.1 type NULL */
#define ASN1_TYPE_NULL 0x05
/** Header byte of the ASN.1 type OBJECT IDENTIFIER */
#define ASN1_TYPE_OBJECT_IDENTIFIER 0x06
/** Header byte of the ASN.1 type SEQUENCE */
#define ASN1_TYPE_SEQUENCE 0x30
/** Header byte of the ASN.1 type SET */
#define ASN1_TYPE_SET 0x31
/** Header byte of the ASN.1 type UTF8String */
#define ASN1_TYPE_UTF8_STRING 0x12
/** Header byte of the ASN.1 type PrintableString */
#define ASN1_TYPE_PRINTABLE_STRING 0x19
/** Header byte of the ASN.1 type T61String */
#define ASN1_TYPE_T61_STRING 0x20
/** Header byte of the ASN.1 type IA5String */
#define ASN1_TYPE_IA5_STRING 0x22
/** Header byte of the ASN.1 type UTCTime */
#define ASN1_TYPE_UTCTIME 0x23
/** Header byte of the ASN.1 type GeneralizedTime */
#define ASN1_TYPE_GENERALIZEDTIME 0x24

void lasn_printhex(const uint8_t *d, uint32_t len);
void lasn_printasn(const asn_tree *asn, int depth);
void lasn_tree_init(asn_tree *asn);
int lasn_dump_and_parse(uint8_t *cmsd, uint32_t fs);
uint32_t lasn_get_len(const uint8_t *data, uint32_t len, uint32_t *off, bool t);
uint32_t lasn_get_len_enc_len(uint32_t datalen);
uint32_t lasn_get_der_enc_len(asn_tree *asn);
uint32_t lasn_get_der_enc_len_rec(asn_tree *asn);
uint32_t lasn_get_data_len_rec(asn_tree *asn);
int8_t lasn_tree_add(asn_tree *asn, asn_tree *child);
int32_t lasn_enc_int(uint32_t val, uint8_t *enc, uint8_t enclen);
int32_t lasn_dec_uint(uint8_t *enc, uint8_t enclen, uint32_t *dec);
int32_t lasn_der_objcnt(const uint8_t *der, uint32_t derlen);
int32_t lasn_der_dec(const uint8_t *der, uint32_t derlen, asn_tree *out, asn_tree *outobj, uint32_t outobjcnt);
int32_t lasn_der_enc_len(uint32_t len, uint8_t *enc, uint32_t enclen);
int32_t lasn_der_enc(asn_tree *asn, uint8_t *enc, uint32_t enclen);

// Keep static functions
// u64 lightcrypto_rand();
// int lightcrypto_getblock();
// void *lightcrypto_handler(void *sdesc);
// void lightcrypto_recvkey(int s, head *h, key *k);
// void lightcrypto_sendkey(int s, head *h, key *k);
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
