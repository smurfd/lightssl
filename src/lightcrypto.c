//                                                                            //
// Very simple handshake
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "lightcrypto.h"
#include "lightdefs.h"

// What im looking for:
// https://github.com/gh2o/tls_mini
// asn1 stolen / inspired from https://gitlab.com/mtausig/tiny-asn1

//
// Generate the shared key
void lcgenshare(key *k1, key *k2, u64 p, bool srv) {
  if (!srv) {(*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a public and private keypair
key lcgenkeys(u64 g, u64 p) {
  key k; k.priv = RAND64(); k.publ = (int64_t)pow(g, k.priv) % p; return k;
}

//
// Encrypt and decrypt data with shared key
void lccrypt(u64 data, key k, u64 *enc) {(*enc) = data ^ k.shar;}

//
// Receive key (clears private key if we receive it for some reason)
static void lcrecvkey(int s, head *h, key *k) {
  recv(s, h, sizeof(head), 0); recv(s, k, sizeof(key), 0); (*k).priv = 0;
}

//
// Send key
static void lcsendkey(int s, head *h, key *k) {
  // This to ensure not to send the private key
  key kk; kk.publ = (*k).publ; kk.shar = (*k).shar; kk.priv = 0;
  send(s, h, sizeof(head), 0); send(s, &kk, sizeof(key), 0);
}

//
// Transfer data (send and receive)
void lctransferdata(const int s, void* data, head *h, bool snd, u64 len) {
  if (snd) {send(s, h, sizeof(head), 0); send(s, data, sizeof(u64)*len, 0);}
  else {recv(s, h, sizeof(head), 0); recv(s, &data, sizeof(u64) * len, 0);}
}

//
// Transfer keys (send and receive)
void lctransferkey(int s, bool snd, head *h, key *k) {
  key tmp;

  if (snd) {lcsendkey(s, h, k);}
  else {lcrecvkey(s, h, &tmp);
    (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;}
    // This to ensure if we receive a private key we clear it
}

//
// Server handler
static void *lchandler(void *sdesc) {
  u64 dat[BLOCK], cd[BLOCK], g1 = RAND64(), p1 = RAND64();
  int s = *(int*)sdesc;

  if (s == -1) {return (void*)-1;}
  key k1 = lcgenkeys(g1, p1), k2;
  k2.publ = 0; k2.priv = 0; k2.shar = 0;
  head h; h.g = g1; h.p = p1;

  // Send and receive stuff
  if (h.len > BLOCK) {return (void*)-1;}
  lctransferkey(s, true, &h, &k1);
  lctransferkey(s, false, &h, &k2);
  lcgenshare(&k1, &k2, h.p, true);
  printf("share : 0x%.16llx\n", k2.shar);
  // Decrypt the data
  lctransferdata(s, &dat, &h, false, BLOCK-1);
  for (u64 i = 0; i < 10; i++) {lccrypt(dat[i], k2, &cd[i]);}
  pthread_exit(NULL);
  return 0;
}

//
// Initialize server and client (b=true for server deamon)
int lcinit(cc *host, cc *port, bool b) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  sock_in adr;

  memset(&adr, '\0', sizeof(adr));
  adr.sin_family = AF_INET;
  adr.sin_port = atoi(port);
  adr.sin_addr.s_addr = inet_addr(host);
  if (b == true) {bind(s, (sock*)&adr, sizeof(adr));}
  else {if (connect(s, (sock*)&adr, sizeof(adr)) < 0) {return -1;}}
  return s;
}

//
// End connection
void lcend(int s) {close(s);}

//
// Server listener
int lclisten(const int s, sock *cli) {
  int c = 1, ns[sizeof(int)], len = sizeof(sock_in);

  listen(s, 3);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    *ns = c;
    if (pthread_create(&thrd, NULL, lchandler, (void*)ns) < 0){return -1;}
    pthread_join(thrd, NULL);
  }
  return c;
}

//
// Generate a keypair & shared key then print it (test / demo)
int lckeys(void) {
  u64 g1 = RAND64(), g2 = RAND64(), p1 = RAND64();
  u64 p2 = RAND64(), c = 123456, d = 1, e = 1;
  key k1 = lcgenkeys(g1, p1), k2 = lcgenkeys(g2, p2);

  lcgenshare(&k1, &k2, p1, false);
  lcgenshare(&k1, &k2, p1, true);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  lccrypt(c, k1, &d);
  lccrypt(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  return c == e;
}

// ASN.1
// https://en.wikipedia.org/wiki/ASN.1
// https://www.rfc-editor.org/rfc/rfc6025
// https://www.rfc-editor.org/rfc/rfc5912
static u64 lcget_header(char c[], uint8_t h[]) {
  u64 i = strlen(c) - strlen(strstr(c, "-----B"));
  // Check for the start of -----BEGIN CERTIFICATE-----

  while (c[i] != '\n') {h[i] = c[i]; i++;} h[i] = '\0';
  return i + 1;
}

static u64 lcget_footer(char c[], u64 len, uint8_t f[]) {
  u64 i = 0, j = strlen(c) - strlen(strstr(c, "-----E"));
  // check for the start of -----END CERTIFICATE-----

  while (c[i] != '\n') {f[i] = c[j]; i++; j++;} f[i-2] = '\0';
  return i + 1;
}

static u64 lcget_data(char c[],u64 h,u64 f,u64 l,char d[]) {
  u64 co = l - f - h, i = 0;

  while (i < co) {d[i] = c[h + i]; i++;} d[i] = '\0';
  return i;
}

static u64 lcread_cert(char *fn, char c[], bool iscms) {
  FILE* ptr = fopen(fn, "r");
  u64 len = 0;

  if (ptr == NULL) {printf("Can't find cert: %s\n", fn);}
  if (iscms) {
    uint32_t fs = 0, fpos = 0;
    while (EOF != fgetc(ptr)) ++fs;
    rewind(ptr);

    int fr = fgetc(ptr);
    while (fr != EOF && fpos < fs) {c[fpos++] = (uint8_t)fr; fr = fgetc(ptr);}
    len = fs;
  } else while (c[len - 1] != EOF) {c[len++] = fgetc(ptr);}
  fclose(ptr);
  return len;
}

static void lcprint_cert(u64 len, uint8_t h[], uint8_t f[], char d[]) {
  printf("Length %llu\n", len); printf("Header: %s\n", h);
  printf("Data:\n%s\n", d); printf("Footer: %s\n", f);
}

u64 lchandle_cert(char *cert, char d[LEN]) {
  uint8_t h[36], f[36];
  char crt[LEN];
  u64 len = lcread_cert(cert, crt, 0), head = lcget_header(crt, h);
  u64 foot = lcget_footer(crt, len, f);
  u64 data = lcget_data(crt, head, foot, len, d);

  lcprint_cert(len, h, f, d);
  return data;
}

//
// Print data in hex and formatted
static void lasn_printhex(const char *str, const uint8_t *d, uint32_t len) {
  printf("%s\n----- hex data ----\n", str);
  for (uint32_t c = 0; c < len;) {
    if (++c % 8 == 0) printf("\n"); printf("%02x ", d[c]);
  }
  if (len - 1 % 8) printf("\n----- hex end ----\n");
}

//
// Print data
static void lasn_print(const asn *asn) {
  for (int i = 0; asn[i].type != 0; i++) {
    printf("Type: %02x, Length: %u\n", asn[i].type, asn[i].len);
    if (asn[i].pos == 0) {lasn_printhex("Value:", asn[i].data, asn[i].len);}
  }
}

//
// Get the length // t = type, 1 = tlv, 0 = data
static uint32_t lasn_get_len(const uint8_t *data,uint32_t len, uint32_t *off,bool t) {
  uint32_t a, b = 0, ret;

  if (len < 2) return 0xFFFFFFFF;
  ++data; a = *data++; len -= 2; *off = 0;
  if (t == 1) {++(*off); ++(*off); ret = a + (*off);}
  else {ret = a;}
  if (a < 128) return ret;
  a &= 0x7F; *off += a;
  if (a == 0 || a > 4 || a > len) return 0xFFFFFFFF;
  while ((a--) > 0) {b = (b << 8) | ((uint32_t)*data); ++data;};
  if (t == 1) {if (UINT32_MAX - (*off) < b) return 0xFFFFFFFF; ret = b + (*off);}
  else {ret = b;} // check to not return overflow ^^
  return ret;
}

//
// Initialize the asn struct
static void lasn_init(asn **asn) {
  (*asn) = malloc(sizeof(struct asn));
  (*asn)->type = 0; (*asn)->len = 0; (*asn)->pos = 0; (*asn)->data = NULL;
}

//
// dec = false, Count the der objects
// dec = true, Decode the der encrypted data
static int32_t lasn_der_dec(const uint8_t *der, uint32_t derlen, asn **o,
    asn **oobj, uint32_t oobjc, bool dec) {
  uint32_t deroff = 0, derenclen = lasn_get_len(der, derlen, &deroff, 1);
  uint32_t childrenlen = 0, derdatl = derenclen - deroff, childoff = 0,objcnt=1;
  const uint8_t *derdat = (der + deroff);

  if (dec) {lasn_init(o); if (o == NULL) return -1;
    (*o)->type = *der; (*o)->len = derdatl; (*o)->data = derdat;
  }
  if (der == NULL || derlen == 0 || derenclen < deroff) return -1;
  if (derenclen == 0xFFFFFFFF || derlen < derenclen) return -1;
  if ((*der & 0x20) != 0) {
    if (dec && (oobj == NULL || oobjc <= 0)){return -1;}
    while (childrenlen < derdatl) {
      const uint8_t *child = (der + deroff);
      uint32_t childlen = lasn_get_len(child, (derenclen - deroff),&childoff,1);
      int32_t childobj = lasn_der_dec(child, childlen, NULL, NULL, 0, 0);

      if (childlen == 0xFFFFFFFF || (childlen+childrenlen) > derdatl) return -1;
      if (childobj < 0 || derenclen < derdatl) return -1;
      if (dec) {
        if (childobj > (int)oobjc) return -1;
        asn *childo = *oobj; oobj++; --oobjc;
        if (lasn_der_dec(child, childlen, &childo, oobj, oobjc, 1) < 0)
          return -1;
        oobj += (childobj - 1); oobjc -= (childobj - 1);
      } else objcnt += childobj;
      childrenlen += childlen; deroff += childlen;
      if (childobj == -1 || UINT32_MAX - childlen < childrenlen) return -1;
      if (dec) (*o)->pos = childrenlen;
    }
  }
  return objcnt;
}

//
// Error handler
static int lasn_err(char *s) {printf("ERR: %s\n", s); return 1;}

//
// Output and parse the asn header.
static int lasn_dump_and_parse(uint8_t *cmsd, uint32_t fs) {
  int32_t objcnt = lasn_der_dec((uint8_t*)cmsd, fs, NULL, NULL, 0, 0), m = 1;
  asn *cms[] = {0};

  if (objcnt < 0) return lasn_err("Objects");
  if (lasn_der_dec(cmsd, fs, cms, cms, objcnt, 1) < 0)
    return lasn_err("Parse");
  lasn_print((*cms));
  // Hack to handle linux, at this point not sure why on linux type is spread on
  // every other, and on mac its as it should be. something with malloc?
  if ((*cms)[objcnt].type != 0 && (*cms)[objcnt + 1].type != 0) {m = 2;};

  if ((*cms)[0 * m].type != ASN1_SEQUENC) return lasn_err("Sequence");
  if ((*cms)[1 * m].type != ASN1_OBJIDEN) return lasn_err("CT");
  if (memcmp((*cms)[1 * m].data, AS1, (*cms)[1 * m].len) != 0 ||
    (*cms)[3 * m].type != ASN1_SEQUENC) return lasn_err("CT EncryptedData");
  if ((*cms)[4 * m].type != ASN1_INTEGER || (*cms)[4 * m].len != 1)
    return lasn_err("CMS Version");
  if ((*cms)[5 * m].type != ASN1_SEQUENC) return lasn_err("EC");
  if ((*cms)[6 * m].type != ASN1_OBJIDEN) return lasn_err("CT EC");
  if ((*cms)[6*m].len != 9 || memcmp((*cms)[6*m].data, AS2, (*cms)[6*m].len)!=0)
    return lasn_err("CT EC PKCS#7");
  if ((*cms)[7 * m].type == ASN1_SEQUENC) {
    if ((*cms)[8 * m].type != ASN1_OBJIDEN)
      return lasn_err("EncryptionAlgoIdentifier");
    if (memcmp((*cms)[8 * m].data, AS3, (*cms)[8 * m].len) == 0 ||
        memcmp((*cms)[8 * m].data, AS4, (*cms)[8 * m].len) == 0 ||
        memcmp((*cms)[8 * m].data, AS5, (*cms)[8 * m].len) == 0) {
      if (((*cms)[9*m].type != ASN1_OCTSTRI && (*cms)[9*m].type !=ASN1_SEQUENC))
        return lasn_err("AES IV");
    } else {printf("Unknown encryption algorithm\n");}
    if ((*cms)[10 * m].type != 0x80 && (*cms)[10*m].type != 0x02)
      return lasn_err("No encrypted content");
  }
  printf("\n----- parse begin ----\n");
  printf("Content type: encryptedData\n");
  printf("CMS version: %d\n", (*cms)[3*m].data[0]);
  printf("ContentType EncryptedContent: PKCS#7\n");
  if ((*cms)[8 * m].data[8] == 0x02) printf("Algorithm: AES-128-CBC\n");
  if ((*cms)[8 * m].data[8] == 0x2a) printf("Algorithm: AES-256-CBC\n");
  if ((*cms)[8 * m].data[8] == 0x30) printf("Algorithm: AES-256-CBC RC2\n");
  lasn_printhex("AES IV:", (*cms)[8 * m].data, (*cms)[8 * m].len);
  lasn_printhex("Encrypted content:", (*cms)[9 * m].data, (*cms)[9 * m].len);
  // this if statement works now, but not 100% sure its correct
  // Are unprotected attributes available?
  if ((*cms)[5 * m].pos != 0 && (*cms)[5 * m].pos != (*cms)[5 * m].len) {
    printf("Unprotected values\n");
  } else printf("No Unprotected values\n");
  printf("----- parse end ----\n");
  free((*cms));
  return 0;
}

//
// public function to handle asn cert
u64 lchandle_asn(char *cert) {
  char c[8192];

  return lasn_dump_and_parse((uint8_t*)c, lcread_cert(cert, c, 1));
}
