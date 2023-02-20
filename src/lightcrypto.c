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

//
// Get BLOCK size
static int lcrypto_getblock() {return BLOCK;}

//
// Random uint64_t
static u64 lcrypto_rand() {
  u64 r = 1;

  for (int i = 0; i < 5; ++i) {r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFF;
}

//
// Generate the shared key
void lcrypto_genshare(key *k1, key *k2, u64 p, bool srv) {
  if (!srv) {(*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a public and private keypair
key lcrypto_genkeys(u64 g, u64 p) {
  key k;

  k.priv = lcrypto_rand(); k.publ = (int64_t)pow(g, k.priv) % p;
  return k;
}

//
// Encrypt and decrypt data with shared key
void lcrypto_crypt(u64 data, key k, u64 *enc) {(*enc) = data ^ k.shar;}

//
// Receive key
static void lcrypto_recvkey(int s, head *h, key *k) {
  recv(s, h, sizeof(head), 0); recv(s, k, sizeof(key), 0); (*k).priv = 0;
  // This to ensure if we receive a private key we clear it
}

//
// Send key
static void lcrypto_sendkey(int s, head *h, key *k) {
  key kk;

  // This to ensure not to send the private key
  kk.publ = (*k).publ; kk.shar = (*k).shar; kk.priv = 0;
  send(s, h, sizeof(head), 0); send(s, &kk, sizeof(key), 0);
}

//
// Transfer data (send and receive)
void lcrypto_transferdata(const int s, void* data, head *h, bool snd, u64 len) {
  if (snd) {send(s, h, sizeof(head), 0); send(s, data, sizeof(u64) * len, 0);}
  else {recv(s, h, sizeof(head), 0); recv(s, &data, sizeof(u64) * len, 0);}
}

//
// Transfer keys (send and receive)
void lcrypto_transferkey(int s, bool snd, head *h, key *k) {
  key tmp;

  if (snd) {lcrypto_sendkey(s, h, k);}
  else {lcrypto_recvkey(s, h, &tmp);
    (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;}
    // This to ensure if we receive a private key we clear it
}

//
// Server handler
static void *lcrypto_handler(void *sdesc) {
  u64 dat[lcrypto_getblock()], cd[lcrypto_getblock()];
  int s = *(int*)sdesc;

  if (s == -1) {return (void*)-1;}
  u64 g1 = lcrypto_rand(), p1 = lcrypto_rand();
  key k1 = lcrypto_genkeys(g1, p1), k2;
  k2.publ = 0; k2.priv = 0; k2.shar = 0;
  head h; h.g = g1; h.p = p1;

  // Send and receive stuff
  if (h.len > BLOCK) {return (void*)-1;}
  lcrypto_transferkey(s, true, &h, &k1);
  lcrypto_transferkey(s, false, &h, &k2);
  lcrypto_genshare(&k1, &k2, h.p, true);
  printf("share : 0x%.16llx\n", k2.shar);
  // Decrypt the data
  lcrypto_transferdata(s, &dat, &h, false, BLOCK-1);
  for (u64 i = 0; i < 10; i++) {lcrypto_crypt(dat[i], k2, &cd[i]);}
  pthread_exit(NULL);
  return 0;
}

//
// Initialize server and client (b=true for server deamon)
int lcrypto_init(cc *host, cc *port, bool b) {
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
void lcrypto_end(int s) {close(s);}

//
// Server listener
int lcrypto_listen(const int s, sock *cli) {
  int c = 1, ns[sizeof(int)], len = sizeof(sock_in);

  listen(s, 3);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    *ns = c;
    if (pthread_create(&thrd, NULL, lcrypto_handler, (void*)ns) < 0){return -1;}
    pthread_join(thrd, NULL);
  }
  return c;
}

//
// Generate a keypair & shared key then print it (test / demo)
int lcrypto_keys() {
  u64 g1 = lcrypto_rand(), g2 = lcrypto_rand(), p1 = lcrypto_rand();
  u64 p2 = lcrypto_rand(), c = 123456, d = 1, e = 1;
  key k1 = lcrypto_genkeys(g1, p1), k2 = lcrypto_genkeys(g2, p2);

  lcrypto_genshare(&k1, &k2, p1, false);
  lcrypto_genshare(&k1, &k2, p1, true);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  lcrypto_crypt(c, k1, &d);
  lcrypto_crypt(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  return c == e;
}

// https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c/66723102#66723102
// UTF8 encode/decode

// from UTF-8 encoding to Unicode Codepoint
u32 utf8decode(u32 c) {
  u32 mask;
  u64 n[] = {0x00EFBFBF, 0x000F0000, 0x003F0000, 0x07000000, 0x00003F00,
    0x0000003F};

  if (c > 0x7F) {
    mask = (c <= n[0]) ? n[1] : n[2];
    c = ((c & n[3]) >> 6) | ((c & mask ) >> 4) | ((c & n[4]) >> 2) | (c & n[5]);
  }
  return c;
}

// From Unicode Codepoint to UTF-8 encoding
u32 utf8encode(u32 cp) {
  u32 c = cp;
  u64 n[] = {0x000003F, 0x0000FC0, 0x003F000, 0x01C0000, 0x0000800, 0x0000C080,
    0x0010000, 0x00E08080, 0xF0808080};

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
static u64 lcrypto_get_header(char c[], u08 h[]) {
  u64 i = 0;

  // Check for the start of -----BEGIN CERTIFICATE-----
  i = strlen(c) - strlen(strstr(c, "-----B"));
  while (c[i] != '\n') {h[i] = c[i]; i++;} h[i] = '\0';
  return i + 1;
}

static u64 lcrypto_get_footer(char c[], u64 len, u08 f[]) {
  u64 i = 0, j = 0;

  // check for the start of -----END CERTIFICATE-----
  j = strlen(c) - strlen(strstr(c, "-----E"));
  while (c[i] != '\n') {f[i] = c[j]; i++; j++;} f[i] = '\0';
  return i + 1;
}

static u64 lcrypto_get_data(char c[], u64 h, u64 f, u64 l, char d[]) {
  u64 co = l - f - h + 1, i = 0;

  while (i < co) {d[i] = c[h + i]; i++;} d[i-1] = '\0';
  return i;
}

static u64 lcrypto_read_cert(char *fn, char c[]) {
  FILE* ptr = fopen(fn, "r");
  u64 len = 0;

  if (ptr == NULL) {printf("Can't find cert: %s\n", fn);}
  while (c[len - 1] != EOF) {c[len++] = fgetc(ptr);}
  fclose(ptr);
  return len;
}

static void lcrypto_print_cert(u64 len, u08 h[], u08 f[], char d[]) {
  printf("Length %llu\n", len); printf("Header: %s\n", h);
  printf("Data: %s\n", d); printf("Footer: %s\n", f);
}

u64 lcrypto_handle_cert(char *cert, char d[LEN]) {
  u64 len = 0, foot, head, data;
  u08 h[36], f[36];
  char crt[LEN];

  len = lcrypto_read_cert(cert, crt);
  head = lcrypto_get_header(crt, h);
  foot = lcrypto_get_footer(crt, len, f);
  data = lcrypto_get_data(crt, head, foot, len, d);
  lcrypto_print_cert(len, h, f, d);
  return data;
}

static u32 lcrypto_oct(int i, int inl, cuc d[257]) {
  if (i < inl) {return d[i];} else {return 0;}
}

static u32 lcrypto_sex(cc d[257], char c[257], int i) {
  if (d[i] == '=') {return 0 & i++;} else {return c[(int)d[i]];}
}

void lcrypto_encode64(cuc *data, int inl, int *ol, char ed[*ol]) {
  static int tab[] = {0, 2, 1};
  u32 a, b, c, tri;

  *ol = 4 * ((inl + 2) / 3);
  for (int i = 0, j = 0; i < inl;) {
    a = lcrypto_oct(i++, inl, data); b = lcrypto_oct(i++, inl, data);
    c = lcrypto_oct(i++, inl, data);
    tri = (a << 0x10) + (b << 0x08) + c;
    for (int k = 3; k >=0; k--) {ed[j++] = enc[(tri >> k * 6) & 0x3F];}
  }
  for (int i = 0; i < tab[inl % 3]; i++) ed[*ol - 1 - i] = '='; ed[*ol] = '\0';
}

void lcrypto_decode64(cc *data, int inl, int *ol, u08 dd[*ol]) {
  static char dec[LEN] = {0};
  u32 a, b, c, d, tri;

  *ol = inl / 4 * 3;
  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') (*ol)--;}
  for (int i = 0; i < 64; i++) dec[(u08)enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    a = lcrypto_sex(data, dec, i++); b = lcrypto_sex(data, dec, i++);
    c = lcrypto_sex(data, dec, i++); d = lcrypto_sex(data, dec, i++);
    tri = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
    if (j < *ol) {for (int k = 2; k >= 0; k--) dd[j++] = (tri >> k * 8) & 0xFF;}
  }
}

// What im looking for:
// https://github.com/gh2o/tls_mini

// ------------
// stolen / inspired from https://gitlab.com/mtausig/tiny-asn1
void printhex(const uint8_t *d, unsigned int len) {
  unsigned int c = 0, bc = 0;

  while(c < len) {
    printf("%02x ", d[c]);
    ++c; ++bc;
    if (bc == 4) printf("  ");
    if (bc == 8) {printf("\n"); bc = 0;}
  }
  printf("\n");
}

void printasn(const asn_tree *asn, int depth) {
  printf("d=%d, Tag: %02x, len=%"PRIu32"\n", depth, asn->type, asn->len);
  if (asn->child == NULL) {
    printf("Value:\n");
    printhex(asn->data, asn->len);
  } else {printasn(asn->child, depth + 1);}
  if (asn->next != NULL) printasn(asn->next, depth);
}

uint32_t get_len(const uint8_t *data, uint32_t len, uint32_t *off, bool t) {
  uint32_t a, b = 0, ret; // t = type, 1 = tlv, 0 = data

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

uint32_t get_len_enc_len(uint32_t datalen) {
  uint32_t len = 1, len1 = datalen;

  do {len1 = len >> 8; ++len;} while(len1 > 0);
  return len;
}

uint32_t get_der_enc_len(asn_tree *asn) {
  return (1 + asn->len + get_len_enc_len(asn->len));
}

uint32_t get_der_enc_len_rec(asn_tree *asn) {
  if (asn == NULL) return 0xFFFFFFFF;
  uint32_t len = get_der_enc_len_rec(asn);
  if (len == 0xFFFFFFFF) return 0xFFFFFFFF;
  return (1 + get_len_enc_len(len) + len);
}

uint32_t get_data_len_rec(asn_tree *asn) {
  if (asn == NULL) return 0xFFFFFFFF;
  if ((asn->type & 0x20) != 0) { // A constructed type
    asn_tree *child = asn->child;
    uint32_t len = 0;

    while(child != NULL){len += get_der_enc_len_rec(child);child = child->next;}
    return len;
  } else {return asn->len;} // Not a constructed type
}

void tree_init(asn_tree *asn) {
  asn->type = 0; asn->len = 0;
  asn->data = NULL; asn->prev = NULL;
  asn->next = NULL; asn->child = NULL; asn->parent = NULL;
}

int8_t tree_add(asn_tree *asn, asn_tree *child) {
  if (asn == NULL || child == NULL) return -1;
  if (asn->child == NULL) {asn->child = child; child->parent = asn; return 0;}
  else {
    asn_tree  *lchild = asn->child;
    while (lchild->next != NULL) {lchild = lchild->next;}
    lchild->next = child;
    child->prev = lchild;
    child->parent = asn;
    return 0;
  }
}

int32_t enc_int(uint32_t val, uint8_t *enc, uint8_t enclen) {
  uint8_t revenc[5], encbytes = 0, padneed = 0, byteneed;

  if (enc == NULL || enclen == 0) return -1;
  if (val == 0) {enc[0] = 0; return 1;}
  while (val > 0) {
    revenc[encbytes] = val % 256; val = val / 256; ++encbytes;
  }
  byteneed = encbytes;
  if (revenc[encbytes - 1] > 0x7F) {padneed = 1; ++byteneed;}
  if (byteneed > enclen) return -2;
  if (padneed != 0) {enc[0] = 0x00; enc++;}
  for (uint8_t i = 0; i < encbytes; ++i) {enc[i] = revenc[encbytes - i - 1];}
  return byteneed;
}

int32_t dec_uint(uint8_t *enc, uint8_t enclen, uint32_t *dec) {
  if (enc == NULL || enclen == 0) return -1;
  if (((enc[0] == 0) && enclen > 5) || ((enc[0] != 0) && enclen > 4)) return -1;
  if (enc[0] & 0x80) return -1;
  *dec = 0;
  while (enclen > 0) {
    *dec *= 256; *dec += *enc;
    ++enc; --enclen;
  }
  return 0;
}

int32_t der_objcnt(const uint8_t *der, uint32_t derlen) {
  uint32_t deroff, derenc_len = get_len(der, derlen, &deroff, 1);
  uint32_t children_len = 0, derdat_len = derenc_len - deroff;
  int32_t objcnt = 1;

  if (der == NULL || derlen == 0) return -1;
  if (derenc_len == 0xFFFFFFFF) return -1;
  if (derlen < derenc_len) return -1;
  if (derenc_len < deroff) return -1;
  if ((*der & 0x20) != 0) {
    while (children_len < derdat_len) {
      const uint8_t *child = (der + deroff);
      uint32_t child_maxlen = derenc_len - deroff, childoff;
      uint32_t child_len = get_len(child, child_maxlen, &childoff, 1);

      if (derenc_len < derdat_len) return -1;
      if (child_len == 0xFFFFFFFF) return -1;
      if ((child_len + children_len) > derdat_len) return -1;
      int32_t child_obj = der_objcnt(child, child_len);
      objcnt += child_obj;
      if (child_obj == -1) return -1;
      if (UINT32_MAX - child_len < children_len) return -1;
      children_len += child_len;
      deroff += child_len;
    }
  }
  return objcnt;
}

int32_t der_dec(const uint8_t *der, uint32_t derlen, asn_tree *out,
    asn_tree *outobj, unsigned int outobjcnt) {
  uint32_t deroff, derenc_len = get_len(der, derlen, &deroff, 1);
  uint32_t children_len = 0, derdat_len = derenc_len - deroff;
  const uint8_t *derdat = (der + deroff);

  if (der == NULL || out == NULL || derlen == 0) return -1;
  if (derenc_len == 0xFFFFFFFF) return -2;
  if (derlen < derenc_len) return -3;
  tree_init(out);
  out->type = *der;
  out->len = derdat_len;
  out->data = derdat;
  if ((*der & 0x20) != 0) {
    if (outobj == NULL || outobjcnt <= 0) return -1;
    while (children_len < derdat_len) {
      const uint8_t *child = (der + deroff);
      uint32_t child_datoff, child_maxlen = (derenc_len - deroff);
      uint32_t child_len = get_len(child, child_maxlen, &child_datoff, 1);
      int32_t child_obj = der_objcnt(child, child_len);

      if (child_len == 0xFFFFFFFF) return -4;
      if ((child_len + children_len) > derdat_len) return -5;
      if (child_obj < 0 || child_obj > (int)outobjcnt) return -6;
      asn_tree *child_o = outobj;
      outobj++; --outobjcnt;
      if (der_dec(child, child_len, child_o, outobj, outobjcnt) < 0) return -7;
      outobj += (child_obj - 1);
      outobjcnt -= (child_obj - 1);
      child_o->parent = out;
      if (out->child == NULL) {out->child = child_o;}
      else {
        asn_tree *lchild = out->child;
        while (lchild->next != NULL) {lchild = lchild->next;}
        lchild->next = child_o;
        lchild->next->prev = lchild;
      }
      children_len += child_len;
      deroff += child_len;
    }
  }
  return 1;
}

int32_t der_enc_len(uint32_t len, uint8_t *enc, uint32_t enclen) {
  uint32_t lenneed = get_len_enc_len(len);

  if (enc == 0 || enclen == 0) return -1;
  if (lenneed > enclen) return -1;
  if (lenneed == 1) {*enc = (uint8_t)len;}
  else {
    *enc = 0x80 + (lenneed - 1); // store nr len bytes
    enc += (lenneed - 1); // store len
    while (len > 0) {*enc = len % 256; len = len / 256; enc--;}
  }
  return (int32_t)lenneed;
}

int32_t der_enc(asn_tree *asn, uint8_t *enc, uint32_t enclen) {
  if (asn == NULL) return -1;
  uint32_t lenneed = get_der_enc_len_rec(asn);
  uint32_t datlen = get_data_len_rec(asn);

  if (lenneed > enclen) return -1;
  if (datlen == 0xFFFFFFFF) return -1;
  *enc = asn->type; enc++; enclen--;
  int32_t len_enc_len = der_enc_len(datlen, enc, enclen);
  if (len_enc_len < 0) return -1;
  enc += len_enc_len; enclen -= len_enc_len;
  if ((asn->type & 0x20) != 0) { // A Constructed type
    asn_tree *child = asn->child;
    while (child != NULL) {
      int32_t child_enclen = der_enc(child, enc, enclen);
      if (child_enclen < 0) return -1;
      enc += child_enclen; enclen -= child_enclen;
    }
  } else { // A Primitive type, copy data
    if (asn->len > 0) {
      if (asn->len <= enclen) {memcpy(enc, asn->data, asn->len);}
      else return -1;
    }
  }
  return (int32_t)lenneed;
}

int dump_and_parse(uint8_t *cmsd, uint32_t fs) {
  int32_t objcnt = der_objcnt(cmsd, fs);
  if (objcnt < 0) {printf("elemnt calc err\n"); free(cmsd); return 1;}
  asn_tree *asnobj = (asn_tree*)malloc(sizeof(asn_tree) * objcnt);
  if (asnobj == NULL) {printf("asn malloc err\n"); free(cmsd); return 1;}
  asn_tree cms;
  if (der_dec(cmsd, fs, &cms, asnobj, objcnt) < 0) {
    printf("cant parse data\n");free(cmsd); return 1;
  }
  printf("----- dump begin ----\n"); printasn(&cms, 0);
  printf("----- parse begin ----\n");
  if (cms.type != ASN1_TYPE_SEQUENCE) {
    printf("outr type != SEQUENCE, %x\n", cms.type); return 1;
  }
  asn_tree *ct = cms.child;
  if (ct == NULL || ct->type != ASN1_TYPE_OBJECT_IDENTIFIER) {
    printf("no contenttype avail\n");
    return 1;
  }
  printf("Content type: ");
  if (memcmp(ct->data, (uint8_t[]){0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
      0x07, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06},
      ct->len) != 0) {
    printf("no contenttype of type encrypteddata avail\n"); return 1;
  }
  printf("encryptedData\n");
  asn_tree *encd = ct->next->child;
  if (encd == NULL || encd->type != ASN1_TYPE_SEQUENCE) {
    printf("no encrypted data avail\n"); return 1;
  }
  asn_tree *cmsv = encd->child;
  if (cmsv == NULL || cmsv->type != ASN1_TYPE_INTEGER || cmsv->len != 1) {
    printf("no cms Version avail\n"); return 1;
  }
  uint8_t v = cmsv->data[0];
  printf("cms version: %d\n", v);
  asn_tree *encci = cmsv->next;
  if (encci == NULL || encci->type != ASN1_TYPE_SEQUENCE) {
    printf("no encrypted content info avai\n"); return 1;
  }
  asn_tree *enccict = encci->child;
  if (enccict == NULL || enccict->type != ASN1_TYPE_OBJECT_IDENTIFIER) {
    printf("no contenttype of encryptedcontentinfo avail\n"); return 1;
  }
  if (enccict->len != 9 || memcmp(enccict->data, (uint8_t[]){0x2a, 0x86, 0x48,
      0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}, enccict->len) != 0) {
    printf("no contenttype of EncrytptedContentInfo of type pkcs#7 avail\n");
    return 1;
  }
  printf("contenttype of encryptedcontentinfo: pkcs#7\n");
  asn_tree *ctencalg = enccict->next;
  if (ctencalg == NULL) {printf("no contentencryption algo avail\n"); return 1;}
  if (ctencalg->type == ASN1_TYPE_SEQUENCE) {
    asn_tree *encalgi = ctencalg->child;
    if (encalgi == NULL || encalgi->type != ASN1_TYPE_OBJECT_IDENTIFIER) {
      printf("no encrypt algo identifier avail\n"); return 1;
    }
    if (memcmp(encalgi->data, (uint8_t[]){0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x01, 0x02}, encalgi->len) == 0) {
      printf("content encrypt algo: AES-128-CBC\n");
      asn_tree *aesiv = encalgi->next;
      if (aesiv == NULL || aesiv->type != ASN1_TYPE_OCTET_STRING) {
        printf("no aes iv avail\n"); return 1;
      }
      printf("AES IV:\n");
      printhex(aesiv->data, aesiv->len);
    } else {printf("unknown encryption algo\n");}
    asn_tree *encct = ctencalg->next;
    if (encct == NULL || encct->type != 0x80) {
      printf("no encr content avail\n"); return 1;
    }
    printf("Encrypted content:\n");
    printhex(encct->data, encct->len);
  }
  asn_tree *unpattr = encci->next;
  if (unpattr != NULL) printf("unprot attributes avail\n");
  else printf("no unprot attributes avail\n");
  free(asnobj); free(cmsd);
  return 0;
}
