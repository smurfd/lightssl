// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
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
#define A1INTEGER 0x02 // Header byte of the ASN.1 type INTEGER
#define A1BITSTRI 0x03 // Header byte of the ASN.1 type BIT STRING
#define A1OCTSTRI 0x04 // Header byte of the ASN.1 type OCTET STRING
#define A1NULL000 0x05 // Header byte of the ASN.1 type NULL
#define A1OBJIDEN 0x06 // Header byte of the ASN.1 type OBJECT IDENTIFIER
#define A1SEQUENC 0x30 // Header byte of the ASN.1 type SEQUENCE
#define A1SET0000 0x31 // Header byte of the ASN.1 type SET
#define A1UTF8STR 0x12 // Header byte of the ASN.1 type UTF8String
#define A1PRNTSTR 0x19 // Header byte of the ASN.1 type PrintableString
#define A1T61STRI 0x20 // Header byte of the ASN.1 type T61String
#define A1IA5STRI 0x22 // Header byte of the ASN.1 type IA5String
#define A1UTCTIME 0x23 // Header byte of the ASN.1 type UTCTime
#define A1GENTIME 0x24 // Header byte of the ASN.1 type GeneralizedTime

static uint8_t AA[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x06};
static uint8_t AB[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01};
static uint8_t AC[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};
static uint8_t AD[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 ,0x2a};
static uint8_t AE[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02 ,0x30};

int crypto_init(const char *host, const char *port, bool b);
void crypto_transfer_key(int s, bool snd, head *h, key *k);
void crypto_transfer_data(const int s, void* data, head *h, bool snd, u64 len);
void crypto_gen_share(key *k1, key *k2, u64 p, bool srv);
key crypto_gen_keys(u64 g, u64 p);
int crypto_gen_keys_local(void);
int crypto_srv_listen(int s, sock *cli);
void cryption(u64 data, key k, u64 *enc);
void crypto_end(int s);

u64 crypto_handle_cert(char d[LEN], const char *cert);
u64 crypto_handle_asn(char c[LEN], const char *cert);
#endif

// Very simple handshake
// asn1 - stolen / inspired from https://gitlab.com/mtausig/tiny-asn1

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
