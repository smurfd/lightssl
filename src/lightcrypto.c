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
int lckeys() {
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

// https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c/66723102#66723102
// UTF8 encode/decode

// from UTF-8 encoding to Unicode Codepoint
uint32_t lcutf8decode(uint32_t c) {
  u64 n[] = {0x00EFBFBF, 0x000F0000, 0x003F0000, 0x07000000, 0x00003F00,
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
  u64 n[] = {0x000003F, 0x0000FC0, 0x003F000, 0x01C0000, 0x0000800,
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
  printf("___ le n %llu\n", len);

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
    printf("d=%d, Tag: %02x, len=%lu\n", depth, asn[i].type, asn[i].len);
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
  printf("LEN1: %lu, %lu, %lu %lu\n", ret, len, a, b);
  if (t == 1) {++(*off); ++(*off); ret = a + (*off);}
  else {ret = a;}
  printf("LEN2: %lu, %lu, %lu %lu\n", ret, len, a, b);
  if (a < 128) return ret;
  a &= 0x7F; *off += a;
  printf("LEN3: %lu, %lu, %lu %lu\n", ret, len, a, b);
  if (a == 0 || a > 4 || a > len) return 0xFFFFFFFF;
  printf("LEN4: %lu, %lu, %lu %lu\n", ret, len, a, b);
  while ((a--) > 0) {b = (b << 8) | ((uint32_t)*data); ++data;};
  printf("LEN5: %lu, %lu, %lu %lu\n", ret, len, a, b);
  if (t == 1) {if (UINT32_MAX - (*off) < b) return 0xFFFFFFFF; ret = b + (*off);}
  else {ret = b;} // check to not return overflow ^^
  printf("LEN6: %lu, %lu, %lu %lu\n", ret, len, a, b);
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
  uint32_t childrenlen = 0, derdatl = derenclen - deroff, childoff = 0;
  const uint8_t *derdat = (der + deroff);
  int32_t objcnt = 1;

  printf("dec1: %lu, %lu, %lu\n", derenclen, derdatl, *derdat);
  if (dec) {
    lasn_init(o); if (o == NULL) return -1;
    (*o)->type = der[0]; (*o)->len = derdatl; (*o)->data = derdat;
  }
  if (der == NULL || derlen == 0 || derenclen < deroff) return -1;
  if (derenclen == 0xFFFFFFFF || derlen < derenclen) return -1;
  if ((*der & 0x20) != 0) {
    if (dec && (oobj == NULL || oobjc <= 0)){return -1;}
    while (childrenlen < derdatl) {
      const uint8_t *child = (der + deroff);
      uint32_t childlen = lasn_get_len(child, (derenclen - deroff),&childoff,1);
      int32_t childobj = lasn_der_dec(child, childlen, NULL, NULL, 0, 0);
      printf("dec2: %lu, %lu, %lu\n", *child, childlen, childobj);

      if (childlen == 0xFFFFFFFF || (childlen+childrenlen) > derdatl) return -1;
      if (childobj < 0 || derenclen < derdatl) return -1;
      if (dec) {
        if (childobj > (int)oobjc) return -1;
        asn *childo = *oobj;
        oobj++; --oobjc;
        if (lasn_der_dec(child, childlen, &childo, oobj, oobjc, 1) < 0) return -1;
        oobj += (childobj - 1); oobjc -= (childobj - 1);
        printf("dec3: %llu, %llu, %d\n", oobjc, childobj, *child);

      } else objcnt += childobj;
      childrenlen += childlen; deroff += childlen;
      if (childobj == -1 || UINT32_MAX - childlen < childrenlen) return -1;
      if (dec) (*o)->pos = childrenlen;
    }
  }
  printf("decxx: %lu, %lu, %lu\n", derenclen, derdatl, *derdat);

  return objcnt;
}

//
// Error handler
static int lasn_err(char *s) {printf("ERR: %s\n", s); return 1;}
static void lasn_print1(asn *a) {
  printf("ASN : %lu %lu %lu\n", a->type, a->len, a->pos);
}
//
// Output and parse the asn header.
static int lasn_dump_and_parse(uint8_t *cmsd, uint32_t fs) {
  int32_t objcnt = lasn_der_dec((uint8_t*)cmsd, fs, NULL, NULL, 0, 0);
  asn *ct[]={0}, *asnobj[]={0}, *cms[]={0}, *encd[]={0}, *aesiv[]={0};
  asn *ci[]={0}, *cmsv[]={0}, *ict[]={0}, *et[]={0}, *algi[]={0}, *alg[]={0};
  asn *cmsnew[]={0};
  //printf("------ %lu\n", (*cms)->type);
  if (objcnt < 0) return lasn_err("Objects");
  if (lasn_der_dec(cmsd, fs, cms, asnobj, objcnt, 1) < 0) return lasn_err("Parse");

lasn_init(cmsnew);
  int j = 0; // 06 00 30
  for (int i = 0; i < 48; i++) {
    (*cmsnew)[j] = (*cms)[i];
    if ((*cms)[i].type==0 && i < 12) j--;
    j++;
  }
  for (int i = 0; i < 48; i++) printf("%02x ", cmsd[i]); printf("\n\n");
  for (int i = 0; i < 48; i++) printf("%02x ", (*cms)->data[i]); printf("\n\n");
  for (int i = 0; i < 48; i++) printf("%02x ", (*cmsnew)[i].type); printf("\n\n");

  printf("\n------11 %lu\n", fs);
  lasn_print1((*cms));
  printf("------11 %lu\n", fs);

  printf("new ---- \n");
  if ((*cmsnew)[0].type != ASN1_SEQUENC) return lasn_err("Sequence");
  if ((*cmsnew)[1].type != ASN1_OBJIDEN) return lasn_err("CT");
  if (memcmp((*cmsnew)[1].data, AS1, (*cmsnew)[1].len) != 0 ||  (*cmsnew)[3].type != ASN1_SEQUENC) return lasn_err("CT EncryptedData");
  if ((*cmsnew)[4].type != ASN1_INTEGER || (*cmsnew)[4].len != 1) return lasn_err("cmsnew Version");
  if ((*cmsnew)[5].type != ASN1_SEQUENC) return lasn_err("EC");
  if ((*cmsnew)[6].type != ASN1_OBJIDEN) return lasn_err("CT EC");
  if ((*cmsnew)[6].len != 9 || memcmp((*cmsnew)[6].data, AS2, (*cmsnew)[6].len) != 0) return lasn_err("CT EC PKCS#7");
  if ((*cmsnew)[7].type == ASN1_SEQUENC) {
    if ((*cmsnew)[8].type != ASN1_OBJIDEN) return lasn_err("EncryptionAlgoIdentifier");
    if (memcmp((*cmsnew)[8].data, AS3, (*cmsnew)[8].len) == 0 ||
        memcmp((*cmsnew)[8].data, AS4, (*cmsnew)[8].len) == 0 ||
        memcmp((*cmsnew)[8].data, AS5, (*cmsnew)[8].len) == 0) {
      if (((*cmsnew)[9].type != ASN1_OCTSTRI && (*cmsnew)[9].type != ASN1_SEQUENC)) return lasn_err("AES IV");
    } else {printf("Unknown encryption algorithm\n");}
    if ((*cmsnew)[10].type != 0x80 && (*cmsnew)[10].type != 0x02) return lasn_err("No encrypted content");
  }
  printf("----- parse begin ----\n");
  printf("Content type: encryptedData\n");
  printf("cmsnew version: %d\n", (*cmsnew)[3].data[0]);
  printf("ContentType EncryptedContent: PKCS#7\n");
  if ((*cmsnew)[8].data[8] == 0x02) printf("Algorithm: AES-128-CBC\n");
  if ((*cmsnew)[8].data[8] == 0x2a) printf("Algorithm: AES-256-CBC\n");
  if ((*cmsnew)[8].data[8] == 0x30) printf("Algorithm: AES-256-CBC RC2\n");
  printf("----- hex begin ----\n");
  lasn_printhex("AES IV:", (*cmsnew)[8].data, (*cmsnew)[8].len);
  lasn_printhex("Encrypted content:", (*cmsnew)[9].data, (*cmsnew)[9].len);
  printf("----- hex begin ----\n");
  // this if statement works now, but not 100% sure its correct
  // Are unprotected attributes available?
  if ((*cmsnew)[5].pos != 0 && (*cmsnew)[5].pos != (*cmsnew)[5].len) printf("Unprot\n");
  else printf("No Unprot\n");
  printf("----- parse end ----\n");
  printf("::: %d %d\n", (*cmsnew)[5].pos, (*cmsnew)[5].len);
  printf("new ---  \n");

  //printf("------ %lu %lu\n", &(*cms)[0]->type, &(*cms)[0]->len);
  printf("------ %lu\n", fs);
  lasn_print((*cms), 0);
  printf("------ %lu\n", fs);
  lasn_print1((*cms));
  printf("------ %lu\n", fs);

  (*ct) = (*cms); (*encd) = &(*ct)[0]; (*cmsv) = &(*encd)[2];
  (*ci) = &(*cmsv)[2]; (*ict) = &(*ci)[2]; (*alg) = &(*ict)[2];
  (*algi) = &(*alg)[2]; (*aesiv) = &(*algi)[2]; (*et) = &(*alg)[0];
  lasn_print1((*cms));
  lasn_print1((*ct));
  lasn_print1((*encd));
  lasn_print1((*cmsv));

  lasn_print1((*ci));
  lasn_print1((*ict));
  lasn_print1((*alg));
  lasn_print1((*algi));

  lasn_print1((*aesiv));
  lasn_print1((*et));

  printf("ci : %d %d\n", (*ci)[1].pos, (*ci)[1].len);
  printf("ctt: %lu %lu %lu\n", (*ct)[0].type, (*ct)[1].type, (*ct)[2].type);
  // _err CT = ContentType, EC = EncryptedContent
  if ((*cms)->type != ASN1_SEQUENC) return lasn_err("Sequence");
  if ((*ct) == NULL || (*ct)[2].type != ASN1_OBJIDEN) return lasn_err("CT");
  printf("encd: %lu %lu %lu : %d\n", (*encd)[0].type, (*encd)[1].type, (*encd)[2].type, memcmp((*ct)[2].data, AS1, (*ct)[2].len));
  if (memcmp((*ct)[2].data, AS1, (*ct)[2].len) != 0 || (*encd) == NULL ||
    (*encd)[0].type != ASN1_SEQUENC) return lasn_err("CT EncryptedData");
  printf("cmsv: %lu %lu %lu\n", (*cmsv)[6].type, (*cmsv)[7].type, (*cmsv)[8].type);


  if ((*cmsv) == NULL || (*cmsv)[6].type != ASN1_INTEGER || (*cmsv)[6].len != 1)
    return lasn_err("CMS Version");
  printf("cmsv: %lu %lu %lu\n", (*ci)[0].type, (*ci)[1].type, (*ci)[2].type);
  if ((*ci) == NULL || (*ci)[2].type != ASN1_SEQUENC) return lasn_err("EC");
  printf("ict: %lu %lu %lu\n", (*ict)[6].type, (*ict)[7].type, (*ict)[8].type);
  if ((*ict) == NULL || (*ict)[6].type != ASN1_OBJIDEN) return lasn_err("CT EC");
  printf("ict: %lu %lu %lu : %d\n", (*ict)[6].len, (*ict)[7].len, (*ict)[8].len, memcmp((*ict)[6].data, AS2, (*ict)[6].len));
  if ((*ict)[6].len != 9 || memcmp((*ict)[6].data, AS2, (*ict)[6].len) != 0)
    return lasn_err("CT EC PKCS#7");
  printf("alg: %lu %lu %lu\n", (*alg)[0].type, (*alg)[1].type, (*alg)[2].type);
  if ((*alg) == NULL) {lasn_err("EncryptionAlgorithm");}
  if ((*alg)[2].type == ASN1_SEQUENC) {
    if ((*algi) == NULL || (*algi)[2].type != ASN1_OBJIDEN)
      return lasn_err("EncryptionAlgoIdentifier");
  printf("alg len: %lu %d\n", (*algi)[6].len, memcmp((*algi)[6].data, AS3, (*algi)[6].len));
  printf("alg len: %lu %d\n", (*algi)[6].len, memcmp((*algi)[6].data, AS4, (*algi)[6].len));
  printf("alg len: %lu %d\n", (*algi)[6].len, memcmp((*algi)[6].data, AS5, (*algi)[6].len));
    if (memcmp((*algi)[6].data, AS3, (*algi)[6].len) == 0 ||
        memcmp((*algi)[6].data, AS4, (*algi)[6].len) == 0 ||
        memcmp((*algi)[6].data, AS5, (*algi)[6].len) == 0) {
  printf("aesiv: %lu %lu %lu\n", (*aesiv)[0].type, (*aesiv)[1].type, (*aesiv)[2].type);
      if ((*aesiv) == NULL || ((*aesiv)[2].type != ASN1_OCTSTRI &&
          (*aesiv)[2].type != ASN1_SEQUENC)) return lasn_err("AES IV");
    } else {printf("Unknown encryption algorithm\n");}
  printf("et: %lu %lu %lu\n", (*et)[0].type, (*et)[1].type, (*et)[2].type);
  printf("et: %lu %lu %lu\n", (*et)[3].type, (*et)[4].type, (*et)[5].type);
  printf("et: %lu %lu %lu\n", (*et)[6].type, (*et)[7].type, (*et)[8].type);
    if ((*et) == NULL || ((*et)[0].type != 0x80 && (*et)[0].type != 0x02))
      return lasn_err("No encrypted content");
  }
  printf("----- parse begin ----\n");
  printf("Content type: encryptedData\n");
  printf("CMS version: %d\n", (*cmsv)[6].data[0]);
  printf("ContentType EncryptedContent: PKCS#7\n");
  if ((*algi)[6].data[8] == 0x02) printf("Algorithm: AES-128-CBC\n");
  if ((*algi)[6].data[8] == 0x2a) printf("Algorithm: AES-256-CBC\n");
  if ((*algi)[6].data[8] == 0x30) printf("Algorithm: AES-256-CBC RC2\n");
  printf("----- hex begin ----\n");
  lasn_printhex("AES IV:", (*aesiv)[2].data, (*aesiv)[2].len);
  lasn_printhex("Encrypted content:", (*et)[2].data, (*et)[2].len);
  printf("----- hex begin ----\n");
  // this if statement works now, but not 100% sure its correct
  // Are unprotected attributes available?
  if ((*ci)[1].pos != 0 && (*ci)[1].pos != (*ci)[1].len) printf("Unprot\n");
  else printf("No Unprot\n");
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
