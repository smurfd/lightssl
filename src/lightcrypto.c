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
void lcgenshare(key *k1, key *k2, uint64_t p, bool srv) {
  if (!srv) {(*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a public and private keypair
key lcgenkeys(uint64_t g, uint64_t p) {
  key k; k.priv = RAND64(); k.publ = (int64_t)pow(g, k.priv) % p; return k;
}

//
// Encrypt and decrypt data with shared key
void lccrypt(uint64_t data, key k, uint64_t *enc) {(*enc) = data ^ k.shar;}

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
void lctransferdata(const int s, void* data, head *h, bool snd, uint64_t len) {
  if (snd) {send(s, h, sizeof(head), 0); send(s, data, sizeof(uint64_t)*len, 0);}
  else {recv(s, h, sizeof(head), 0); recv(s, &data, sizeof(uint64_t) * len, 0);}
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
  uint64_t dat[BLOCK], cd[BLOCK], g1 = RAND64(), p1 = RAND64();
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
  for (uint64_t i = 0; i < 10; i++) {lccrypt(dat[i], k2, &cd[i]);}
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
int lckeys() {
  uint64_t g1 = RAND64(), g2 = RAND64(), p1 = RAND64();
  uint64_t p2 = RAND64(), c = 123456, d = 1, e = 1;
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

// https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c/66723102#66723102
// UTF8 encode/decode

// from UTF-8 encoding to Unicode Codepoint
uint32_t lcutf8decode(uint32_t c) {
  uint64_t n[] = {0x00EFBFBF, 0x000F0000, 0x003F0000, 0x07000000, 0x00003F00,
    0x0000003F};
  uint32_t mask;

  if (c > 0x7F) {
    mask = (c <= n[0]) ? n[1] : n[2];
    c = ((c & n[3]) >> 6) | ((c & mask ) >> 4) | ((c & n[4]) >> 2) | (c & n[5]);
  }
  return c;
}

// From Unicode Codepoint to UTF-8 encoding
uint32_t lcutf8encode(uint32_t cp) {
  uint64_t n[] = {0x000003F, 0x0000FC0, 0x003F000, 0x01C0000, 0x0000800,
    0x0000C080, 0x0010000, 0x00E08080, 0xF0808080};
  uint32_t c = cp;

  if (cp > 0x7F) {
    c = (cp & n[0]) | (cp & n[1]) << 2 | (cp & n[2]) << 4 | (cp & n[3]) << 6;
    if (cp < n[4]) c |= n[5]; else if (cp < n[6]) c |= n[7]; else c |= n[8];
  }
  return c;
}

// ASN.1
// https://en.wikipedia.org/wiki/ASN.1
// https://www.rfc-editor.org/rfc/rfc6025
// https://www.rfc-editor.org/rfc/rfc5912
static uint64_t lcget_header(char c[], uint8_t h[]) {
  uint64_t i = strlen(c) - strlen(strstr(c, "-----B"));
  // Check for the start of -----BEGIN CERTIFICATE-----

  while (c[i] != '\n') {h[i] = c[i]; i++;} h[i] = '\0';
  return i + 1;
}

static uint64_t lcget_footer(char c[], uint64_t len, uint8_t f[]) {
  uint64_t i = 0, j = strlen(c) - strlen(strstr(c, "-----E"));
  // check for the start of -----END CERTIFICATE-----

  while (c[i] != '\n') {f[i] = c[j]; i++; j++;} f[i-2] = '\0';
  return i + 1;
}

static uint64_t lcget_data(char c[],uint64_t h,uint64_t f,uint64_t l,char d[]) {
  uint64_t co = l - f - h, i = 0;

  while (i < co) {d[i] = c[h + i]; i++;} d[i] = '\0';
  return i;
}

static uint64_t lcread_cert(char *fn, char c[], bool iscms) {
  FILE* ptr = fopen(fn, "r");
  uint64_t len = 0;

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

static void lcprint_cert(uint64_t len, uint8_t h[], uint8_t f[], char d[]) {
  printf("Length %llu\n", len); printf("Header: %s\n", h);
  printf("Data:\n%s\n", d); printf("Footer: %s\n", f);
}

uint64_t lchandle_cert(char *cert, char d[LEN]) {
  uint8_t h[36], f[36];
  char crt[LEN];
  uint64_t len = lcread_cert(cert, crt, 0), head = lcget_header(crt, h);
  uint64_t foot = lcget_footer(crt, len, f);
  uint64_t data = lcget_data(crt, head, foot, len, d);

  lcprint_cert(len, h, f, d);
  return data;
}

static uint32_t lcoct(int i, int inl, cuc d[257]) {
  if (i < inl) {return d[i];} else {return 0;}
}

static uint32_t lcsex(cc d[257], char c[257], int i) {
  if (d[i] == '=') {return 0 & i++;} else {return c[(int)d[i]];}
}

void lcencode64(cuc *data, int inl, int *ol, char ed[*ol]) {
  static int tab[] = {0, 2, 1};

  *ol = 4 * ((inl + 2) / 3);
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = lcoct(i++, inl, data), b = lcoct(i++, inl, data);
    uint32_t c = lcoct(i++, inl, data), tri = (a << 0x10) + (b << 0x08) + c;
    for (int k = 3; k >=0; k--) {ed[j++] = enc[(tri >> k * 6) & 0x3F];}
  }
  for (int i = 0; i < tab[inl % 3]; i++) ed[*ol - 1 - i] = '='; ed[*ol] = '\0';
}

void lcdecode64(cc *data, int inl, int *ol, uint8_t dd[*ol]) {
  static char dec[LEN] = {0};

  *ol = inl / 4 * 3;
  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') (*ol)--;}
  for (int i = 0; i < 64; i++) dec[(uint8_t)enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = lcsex(data, dec, i++), b = lcsex(data, dec, i++);
    uint32_t c = lcsex(data, dec, i++), d = lcsex(data, dec, i++);
    uint32_t tri = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
    if (j < *ol) {for (int k = 2; k >= 0; k--) dd[j++] = (tri >> k * 8) & 0xFF;}
  }
}

//
// Print data in hex and formatted
static void lasn_printhex(const char *str, const uint8_t *d, uint32_t len) {
  uint32_t c = 0;

  printf("%s\n----- hex data ----\n", str);
  while(c < len) {printf("%02x ", d[c]); if (++c % 8 == 0) printf("\n");}
  if (c % 8) printf("\n"); printf("----- hex end ----\n");
}

//
// Print data
static void lasn_print(const asn *asn, int depth) {
  int i = 0;

  while (asn[i].type != 0) {
    printf("d=%d, Tag: %02x, len=%u\n", depth, asn[i].type, asn[i].len);
    if (asn[i].pos == 0) {lasn_printhex("Value:", asn[i].data, asn[i].len);}
    i++;
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
  uint32_t deroff, derenclen = lasn_get_len(der, derlen, &deroff, 1);
  uint32_t childrenlen = 0, derdatl = derenclen - deroff, childoff;
  const uint8_t *derdat = (der + deroff);
  int32_t objcnt = 1;

  if (dec) {
    lasn_init(o); if (o == NULL) return -1;
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
        asn *childo = *oobj;
        oobj++; --oobjc;
        if (lasn_der_dec(child, childlen, &childo, oobj, oobjc, 1) < 0) return -1;
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
  int32_t objcnt = lasn_der_dec((uint8_t*)cmsd, fs, NULL, NULL, 0, 0);
  asn *ct[]={0}, *asnobj[]={0}, *cms[]={0}, *encd[]={0}, *aesiv[]={0};
  asn *ci[]={0}, *cmsv[]={0}, *ict[]={0}, *et[]={0}, *algi[]={0}, *alg[]={0};

  if (objcnt < 0) return lasn_err("Objects");
  if (lasn_der_dec(cmsd, fs, cms, asnobj, objcnt, 1) < 0) return lasn_err("Parse");
  lasn_print((*cms), 0);
  (*ct) = (*cms); (*encd) = &(*ct)[2]; (*cmsv) = &(*encd)[1];
  (*ci) = &(*cmsv)[1]; (*ict) = &(*ci)[1]; (*alg) = &(*ict)[1];
  (*algi) = &(*alg)[1]; (*aesiv) = &(*algi)[1]; (*et) = &(*alg)[3];

  // _err CT = ContentType, EC = EncryptedContent
  if ((*cms)->type != ASN1_SEQUENC) return lasn_err("Sequence");
  if ((*ct) == NULL || (*ct)[1].type != ASN1_OBJIDEN) return lasn_err("CT");
  if (memcmp((*ct)[1].data, AS1, (*ct)[1].len) != 0 || (*encd) == NULL ||
    (*encd)[1].type != ASN1_SEQUENC) return lasn_err("CT EncryptedData");
  if ((*cmsv) == NULL || (*cmsv)[1].type != ASN1_INTEGER || (*cmsv)[1].len != 1)
    return lasn_err("CMS Version");
  if ((*ci) == NULL || (*ci)[1].type != ASN1_SEQUENC) return lasn_err("EC");
  if ((*ict) == NULL || (*ict)[1].type != ASN1_OBJIDEN) return lasn_err("CT EC");
  if ((*ict)[1].len != 9 || memcmp((*ict)[1].data, AS2, (*ict)[1].len) != 0)
    return lasn_err("CT EC PKCS#7");
  if ((*alg) == NULL) {lasn_err("EncryptionAlgorithm");}
  if ((*alg)[1].type == ASN1_SEQUENC) {
    if ((*algi) == NULL || (*algi)[1].type != ASN1_OBJIDEN)
      return lasn_err("EncryptionAlgoIdentifier");
    if (memcmp((*algi)[1].data, AS3, (*algi)[1].len) == 0 ||
        memcmp((*algi)[1].data, AS4, (*algi)[1].len) == 0 ||
        memcmp((*algi)[1].data, AS5, (*algi)[1].len) == 0) {
      if ((*aesiv) == NULL || ((*aesiv)[1].type != ASN1_OCTSTRI &&
          (*aesiv)[1].type != ASN1_SEQUENC)) return lasn_err("AES IV");
    } else {printf("Unknown encryption algorithm\n");}
    if ((*et) == NULL || ((*et)[1].type != 0x80 && (*et)[1].type != 0x02))
      return lasn_err("No encrypted content");
  }
  printf("----- parse begin ----\n");
  printf("Content type: encryptedData\n");
  printf("CMS version: %d\n", (*cmsv)[1].data[0]);
  printf("ContentType EncryptedContent: PKCS#7\n");
  if ((*algi)[1].data[8] == 0x02) printf("Algorithm: AES-128-CBC\n");
  if ((*algi)[1].data[8] == 0x2a) printf("Algorithm: AES-256-CBC\n");
  if ((*algi)[1].data[8] == 0x30) printf("Algorithm: AES-256-CBC RC2\n");
  lasn_printhex("AES IV:", (*aesiv)[1].data, (*aesiv)[1].len);
  lasn_printhex("Encrypted content:", (*et)[0].data, (*et)[0].len);
  // this if statement works now, but not 100% sure its correct
  // Are unprotected attributes available?
  if ((*ci)[2].pos != 0 && (*ci)[2].pos != (*ci)[2].len) printf("Unprot\n");
  else printf("No Unprot\n");
  printf("----- parse end ----\n");
  free((*cms));
  return 0;
}

//
// public function to handle asn cert
uint64_t lchandle_asn(char *cert) {
  char c[8192];

  return lasn_dump_and_parse((uint8_t*)c, lcread_cert(cert, c, 1));
}

// Save static functions that isnt used
/*
static uint32_t lasn_get_len_enc_len(uint32_t datalen) {
  uint32_t len = 1, len1 = datalen;

  while(len1 > 0) {len1 = len >> 8; ++len;}
  return len;
}

static uint32_t lasn_get_der_enc_len(asn *asn) {
  return (1 + (*asn).len + lasn_get_len_enc_len((*asn).len));
}

static int8_t lasn_add(asn **asn, asn **child) {
  if (asn == NULL || child == NULL) return -1;
  if ((*asn-1) == NULL) {memcpy((*asn-1), child, sizeof(struct asn)); memcpy(&(*child)[0], asn, sizeof (struct asn)); return 0;}
  else {
    asn *lchild = *(&(*asn)-1);
    while (&(*lchild)+1 != NULL) {lchild = &(*lchild)+1;}
    memcpy(&(*lchild), child, sizeof(struct asn));
    memcpy(&(*child)-1, &lchild, sizeof(struct asn));
    memcpy(&(*child)[0], asn, sizeof(struct asn));
    return 0;
  }
}

static int32_t lasn_enc_int(uint32_t val, uint8_t *enc, uint8_t enclen) {
  uint8_t revenc[5], encbytes = 0, padneed = 0, byteneed;

  if (enc == NULL || enclen == 0) return -1;
  if (val == 0) {enc[0] = 0; return 1;}
  while (val > 0) {revenc[encbytes] = val % 256; val = val / 256; ++encbytes;}
  byteneed = encbytes;
  if (revenc[encbytes - 1] > 0x7F) {padneed = 1; ++byteneed;}
  if (byteneed > enclen) return -2;
  if (padneed != 0) {enc[0] = 0x00; enc++;}
  for (uint8_t i = 0; i < encbytes; ++i) {enc[i] = revenc[encbytes - i - 1];}
  return byteneed;
}

static int32_t lasn_dec_uint(uint8_t *enc, uint8_t enclen, uint32_t *dec) {
  if (enc == NULL || enclen == 0) return -1;
  if (((enc[0] == 0) && enclen > 5) || ((enc[0] != 0) && enclen > 4)) return -1;
  if (enc[0] & 0x80) return -1;
  *dec = 0;
  while (enclen > 0) {*dec *= 256; *dec += *enc; ++enc; --enclen;}
  return 0;
}

static uint32_t lasn_get_der_enc_len_rec(asn *asn) {
  if (asn == NULL) return 0xFFFFFFFF;
  uint32_t len = lasn_get_der_enc_len_rec(asn);
  if (len == 0xFFFFFFFF) return 0xFFFFFFFF;
  return (1 + lasn_get_len_enc_len(len) + len);
}

static uint32_t lasn_get_data_len_rec(asn *asn) {
  if (asn == NULL) return 0xFFFFFFFF;
  if (((*asn).type & 0x20) != 0) { // A constructed type
    asn *child = &(*asn)-1;
    uint32_t len = 0;

    while(child != NULL) {
      len += lasn_get_der_enc_len_rec(child); child = &(*child)+1;
    }
    return len;
  } else {return (*asn).len;} // Not a constructed type
}

static int32_t lasn_der_enc_len(uint32_t len, uint8_t *enc, uint32_t enclen) {
  uint32_t lenneed = lasn_get_len_enc_len(len);

  if (enc == 0 || enclen == 0 || lenneed > enclen) return -1;
  if (lenneed == 1) {*enc = (uint8_t)len;}
  else {
    *enc = 0x80 + (lenneed - 1); // store nr len bytes
    enc += (lenneed - 1); // store len
    while (len > 0) {*enc = len % 256; len = len / 256; enc--;}
  }
  return (int32_t)lenneed;
}

static int32_t lasn_der_enc(asn **asn, uint8_t *enc, uint32_t enclen) {
  uint32_t lenneed = lasn_get_der_enc_len_rec(*asn);
  uint32_t datlen = lasn_get_data_len_rec(*asn);

  if (asn == NULL || lenneed > enclen || datlen == 0xFFFFFFFF) return -1;
  *enc = (*asn)->type; enc++; enclen--;
  int32_t len_enc_len = lasn_der_enc_len(datlen, enc, enclen);
  if (len_enc_len < 0) return -1;
  enc += len_enc_len; enclen -= len_enc_len;
  if (((*asn)->type & 0x20) != 0) { // A Constructed type
    asn *child = *(&(*asn)-1);
    while (child != NULL) {
      int32_t child_enclen = lasn_der_enc(&child, enc, enclen);
      if (child_enclen < 0) return -1;
      enc += child_enclen; enclen -= child_enclen;
    }
  } else { // A Primitive type, copy data
    if ((*asn)->len > 0) {
      if ((*asn)->len <= enclen) {memcpy(enc, (*asn)->data, (*asn)->len);}
      else {return -1;}
    }
  }
  return (int32_t)lenneed;
}
*/
