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
static uint64_t lcrypto_rand() {
  uint64_t r = 1;

  for (int i = 0; i < 5; ++i) {r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFF;
}

//
// Generate the shared key
void lcrypto_genshare(key *k1, key *k2, uint64_t p, bool srv) {
  if (!srv) {(*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a public and private keypair
key lcrypto_genkeys(uint64_t g, uint64_t p) {
  key k;

  k.priv = lcrypto_rand(); k.publ = (int64_t)pow(g, k.priv) % p;
  return k;
}

//
// Encrypt and decrypt data with shared key
void lcrypto_crypt(uint64_t data, key k, uint64_t *enc) {(*enc) = data ^ k.shar;}

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
void lcrypto_transferdata(const int s, void* data, head *h, bool snd,
  uint64_t len) {
  if (snd) {send(s, h, sizeof(head), 0); send(s, data, sizeof(uint64_t)*len, 0);}
  else {recv(s, h, sizeof(head), 0); recv(s, &data, sizeof(uint64_t) * len, 0);}
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
  uint64_t dat[lcrypto_getblock()], cd[lcrypto_getblock()];
  int s = *(int*)sdesc;

  if (s == -1) {return (void*)-1;}
  uint64_t g1 = lcrypto_rand(), p1 = lcrypto_rand();
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
  for (uint64_t i = 0; i < 10; i++) {lcrypto_crypt(dat[i], k2, &cd[i]);}
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
  uint64_t g1 = lcrypto_rand(), g2 = lcrypto_rand(), p1 = lcrypto_rand();
  uint64_t p2 = lcrypto_rand(), c = 123456, d = 1, e = 1;
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
uint32_t utf8decode(uint32_t c) {
  uint32_t mask;
  uint64_t n[] = {0x00EFBFBF, 0x000F0000, 0x003F0000, 0x07000000, 0x00003F00,
    0x0000003F};

  if (c > 0x7F) {
    mask = (c <= n[0]) ? n[1] : n[2];
    c = ((c & n[3]) >> 6) | ((c & mask ) >> 4) | ((c & n[4]) >> 2) | (c & n[5]);
  }
  return c;
}

// From Unicode Codepoint to UTF-8 encoding
uint32_t utf8encode(uint32_t cp) {
  uint32_t c = cp;
  uint64_t n[] = {0x000003F, 0x0000FC0, 0x003F000, 0x01C0000, 0x0000800,
    0x0000C080, 0x0010000, 0x00E08080, 0xF0808080};

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
static uint64_t lcrypto_get_header(char c[], uint8_t h[]) {
  uint64_t i = 0;

  // Check for the start of -----BEGIN CERTIFICATE-----
  i = strlen(c) - strlen(strstr(c, "-----B"));
  while (c[i] != '\n') {h[i] = c[i]; i++;} h[i] = '\0';
  return i + 1;
}

static uint64_t lcrypto_get_footer(char c[], uint64_t len, uint8_t f[]) {
  uint64_t i = 0, j = 0;

  // check for the start of -----END CERTIFICATE-----
  j = strlen(c) - strlen(strstr(c, "-----E"));
  while (c[i] != '\n') {f[i] = c[j]; i++; j++;} f[i] = '\0';
  return i + 1;
}

static uint64_t lcrypto_get_data(char c[], uint64_t h, uint64_t f, uint64_t l,
  char d[]) {
  uint64_t co = l - f - h + 1, i = 0;

  while (i < co) {d[i] = c[h + i]; i++;} d[i-1] = '\0';
  return i;
}

static uint64_t lcrypto_read_cert(char *fn, char c[], bool iscms) {
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

static void lcrypto_print_cert(uint64_t len, uint8_t h[], uint8_t f[], char d[]) {
  printf("Length %llu\n", len); printf("Header: %s\n", h);
  printf("Data: %s\n", d); printf("Footer: %s\n", f);
}

uint64_t lcrypto_handle_cert(char *cert, char d[LEN]) {
  uint64_t len = 0, foot, head, data;
  uint8_t h[36], f[36];
  char crt[LEN];

  len = lcrypto_read_cert(cert, crt, 0);
  head = lcrypto_get_header(crt, h);
  foot = lcrypto_get_footer(crt, len, f);
  data = lcrypto_get_data(crt, head, foot, len, d);
  lcrypto_print_cert(len, h, f, d);
  return data;
}

static uint32_t lcrypto_oct(int i, int inl, cuc d[257]) {
  if (i < inl) {return d[i];} else {return 0;}
}

static uint32_t lcrypto_sex(cc d[257], char c[257], int i) {
  if (d[i] == '=') {return 0 & i++;} else {return c[(int)d[i]];}
}

void lcrypto_encode64(cuc *data, int inl, int *ol, char ed[*ol]) {
  static int tab[] = {0, 2, 1};
  uint32_t a, b, c, tri;

  *ol = 4 * ((inl + 2) / 3);
  for (int i = 0, j = 0; i < inl;) {
    a = lcrypto_oct(i++, inl, data); b = lcrypto_oct(i++, inl, data);
    c = lcrypto_oct(i++, inl, data);
    tri = (a << 0x10) + (b << 0x08) + c;
    for (int k = 3; k >=0; k--) {ed[j++] = enc[(tri >> k * 6) & 0x3F];}
  }
  for (int i = 0; i < tab[inl % 3]; i++) ed[*ol - 1 - i] = '='; ed[*ol] = '\0';
}

void lcrypto_decode64(cc *data, int inl, int *ol, uint8_t dd[*ol]) {
  static char dec[LEN] = {0};
  uint32_t a, b, c, d, tri;

  *ol = inl / 4 * 3;
  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') (*ol)--;}
  for (int i = 0; i < 64; i++) dec[(uint8_t)enc[i]] = i;
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
void lasn_printhex(const uint8_t *d, uint32_t len) {
  uint32_t c = 0, bc = 0;

  printf("----- dump begin ----\n");
  while(c < len) {
    printf("%02x ", d[c]);
    ++c; ++bc;
    if (bc == 4) printf("  ");
    if (bc == 8) {printf("\n"); bc = 0;}
  }
  printf("\n----- dump end ----\n");
}

void lasn_print_arr(const asn_arr *asn, int depth) {
  int i = 0;

  while (asn[i].type != 0) {
    printf("d=%d, Tag: %02x, len=%"PRIu32"\n", depth, asn[i].type, asn[i].len);
    if (asn[i].pos == 0) {printf("Value:\n");lasn_printhex(asn[i].data, asn[i].len);}
    i++;
  }
}

uint32_t lasn_get_len(const uint8_t *data, uint32_t len, uint32_t *off, bool t) {
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

uint32_t lasn_get_len_enc_len(uint32_t datalen) {
  uint32_t len = 1, len1 = datalen;

  while(len1 > 0) {len1 = len >> 8; ++len;}
  return len;
}

uint32_t lasn_get_der_enc_len_arr(asn_arr *asn) {
  return (1 + (*asn).len + lasn_get_len_enc_len((*asn).len));
}

uint32_t lasn_get_der_enc_len_rec_arr(asn_arr *asn) {
  if (asn == NULL) return 0xFFFFFFFF;
  uint32_t len = lasn_get_der_enc_len_rec_arr(asn);
  if (len == 0xFFFFFFFF) return 0xFFFFFFFF;
  return (1 + lasn_get_len_enc_len(len) + len);
}

uint32_t lasn_get_data_len_rec_arr(asn_arr *asn) {
  if (asn == NULL) return 0xFFFFFFFF;
  if (((*asn).type & 0x20) != 0) { // A constructed type
    asn_arr *child = &(*asn)-1;
    uint32_t len = 0;

    while(child != NULL) {
      len += lasn_get_der_enc_len_rec_arr(child); child = &(*child)+1;
    }
    return len;
  } else {return (*asn).len;} // Not a constructed type
}

void lasn_tree_init_arr(asn_arr **asn) {
  (*asn) = malloc(sizeof(struct asn_arr));
  (*asn)->type = 0; (*asn)->len = 0; (*asn)->pos = 0; (*asn)->data = NULL;
}

int8_t lasn_tree_add_arr(asn_arr **asn, asn_arr **child) {
  if (asn == NULL || child == NULL) return -1;
  if ((*asn-1) == NULL) {memcpy((*asn-1), child, sizeof(struct asn_arr)); memcpy(&(*child)[0], asn, sizeof (struct asn_arr)); return 0;}
  else {
    asn_arr *lchild = *(&(*asn)-1);
    while (&(*lchild)+1 != NULL) {lchild = &(*lchild)+1;}
    memcpy(&(*lchild), child, sizeof(struct asn_arr));
    memcpy(&(*child)-1, &lchild, sizeof(struct asn_arr));
    memcpy(&(*child)[0], asn, sizeof(struct asn_arr));
    return 0;
  }
}

int32_t lasn_enc_int(uint32_t val, uint8_t *enc, uint8_t enclen) {
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

int32_t lasn_dec_uint(uint8_t *enc, uint8_t enclen, uint32_t *dec) {
  if (enc == NULL || enclen == 0) return -1;
  if (((enc[0] == 0) && enclen > 5) || ((enc[0] != 0) && enclen > 4)) return -1;
  if (enc[0] & 0x80) return -1;
  *dec = 0;
  while (enclen > 0) {*dec *= 256; *dec += *enc; ++enc; --enclen;}
  return 0;
}

int32_t lasn_der_objcnt(const uint8_t *der, uint32_t derlen) {
  uint32_t deroff, derenc_len = lasn_get_len(der, derlen, &deroff, 1);
  uint32_t children_len = 0, derdat_len = derenc_len - deroff;
  int32_t objcnt = 1;

  if (der == NULL || derlen == 0 || derenc_len == 0xFFFFFFFF) return -1;
  if (derlen < derenc_len || derenc_len < deroff) return -1;
  if ((*der & 0x20) != 0) {
    while (children_len < derdat_len) {
      const uint8_t *child = (der + deroff);
      uint32_t child_maxlen = derenc_len - deroff, childoff;
      uint32_t child_len = lasn_get_len(child, child_maxlen, &childoff, 1);

      if (derenc_len < derdat_len || child_len == 0xFFFFFFFF) return -1;
      if ((child_len + children_len) > derdat_len) return -1;
      int32_t child_obj = lasn_der_objcnt(child, child_len);
      objcnt += child_obj;
      if (child_obj == -1 || UINT32_MAX - child_len < children_len) return -1;
      children_len += child_len;
      deroff += child_len;
    }
  }
  return objcnt;
}

int32_t lasn_der_dec_arr(const uint8_t *der, uint32_t derlen, asn_arr **out,
    asn_arr **outobj, uint32_t outobjcnt) {
  uint32_t deroff, derenc_len = lasn_get_len(der, derlen, &deroff, 1);
  uint32_t children_len = 0, derdat_len = derenc_len - deroff;
  const uint8_t *derdat = (der + deroff);

  lasn_tree_init_arr(out);
  if (der == NULL || out == NULL || derlen == 0) return -1;
  if (derenc_len == 0xFFFFFFFF) return -2;
  if (derlen < derenc_len) return -3;
  (*out)->type = *der;
  (*out)->len = derdat_len;
  (*out)->data = derdat;
  if ((*der & 0x20) != 0) {
    if (outobj == NULL || outobjcnt <= 0) return -1;

    while (children_len < derdat_len) {
      const uint8_t *child = (der + deroff);
      uint32_t child_datoff, child_maxlen = (derenc_len - deroff);
      uint32_t child_len = lasn_get_len(child, child_maxlen, &child_datoff, 1);
      int32_t child_obj = lasn_der_objcnt(child, child_len);

      if (child_len == 0xFFFFFFFF) return -4;
      if ((child_len + children_len) > derdat_len) return -5;
      if (child_obj < 0 || child_obj > (int)outobjcnt) return -6;
      asn_arr *child_o = *outobj;
      outobj++; --outobjcnt;
      if (lasn_der_dec_arr(child, child_len, &child_o, outobj, outobjcnt) < 0)
        return -7;
      outobj += (child_obj - 1);
      outobjcnt -= (child_obj - 1);
      children_len += child_len;
      deroff += child_len;
      (*out)->pos = children_len;
    }
  }
  return 1;
}

int32_t lasn_der_enc_len(uint32_t len, uint8_t *enc, uint32_t enclen) {
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

int32_t lasn_der_enc_arr(asn_arr **asn, uint8_t *enc, uint32_t enclen) {
  uint32_t lenneed = lasn_get_der_enc_len_rec_arr(*asn);
  uint32_t datlen = lasn_get_data_len_rec_arr(*asn);

  if (asn == NULL || lenneed > enclen || datlen == 0xFFFFFFFF) return -1;
  *enc = (*asn)->type; enc++; enclen--;
  int32_t len_enc_len = lasn_der_enc_len(datlen, enc, enclen);
  if (len_enc_len < 0) return -1;
  enc += len_enc_len; enclen -= len_enc_len;
  if (((*asn)->type & 0x20) != 0) { // A Constructed type
    asn_arr *child = *(&(*asn)-1);
    while (child != NULL) {
      int32_t child_enclen = lasn_der_enc_arr(&child, enc, enclen);
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

int lasn_dump_and_parse_arr(uint8_t *cmsd, uint32_t fs) {
  int32_t objcnt = lasn_der_objcnt((uint8_t*)cmsd, fs);
  asn_arr *ct[] = {0}, *asnobj[] = {0}, *cms[] = {0}, *encd[] = {0};
  asn_arr *encci[] = {0}, *cmsv[] = {0}, *enccict[] = {0}, *aesiv[] = {0};
  asn_arr *ctencalg[] = {0}, *encalgi[] = {0}, *encct[] = {0};

  if (objcnt < 0) {printf("ERR: Objects\n"); return 1;}
  if (lasn_der_dec_arr(cmsd, fs, cms, asnobj, objcnt) < 0) {
    printf("ERR: Parse\n");return 1;
  }
  lasn_print_arr((*cms), 0);
  printf("----- parse begin ----\n");
  if ((*cms)->type != ASN1_TYPE_SEQUENCE) {
    printf("ERR: Sequence, %x\n", (*cms)->type); return 1;
  }
  (*ct) = (*cms);
  if ((*ct) == NULL || (*ct)[1].type != ASN1_TYPE_OBJECT_IDENTIFIER) {
    printf("ERR: ContentType\n"); return 1;
  }
  if (memcmp((*ct)[1].data, AS1, (*ct)[1].len) != 0) {
    printf("ERR: CT EncryptedData\n"); return 1;
  }
  printf("Content type: encryptedData\n");
  (*encd) = &(*ct)[2];
  if ((*encd) == NULL || (*encd)[1].type != ASN1_TYPE_SEQUENCE) {
    printf("ERR: CT EncryptedData\n"); return 1;
  }
  (*cmsv) = &(*encd)[1];
  if ((*cmsv) == NULL || (*cmsv)[1].type != ASN1_TYPE_INTEGER || (*cmsv)[1].len != 1) {
    printf("ERR: CSMVersion\n"); return 1;
  }
  printf("cms version: %d\n", (*cmsv)[1].data[0]);
  (*encci) = &(*cmsv)[1];
  if ((*encci) == NULL || (*encci)[1].type != ASN1_TYPE_SEQUENCE) {
    printf("ERR: EncryptedContent\n"); return 1;
  }
  (*enccict) = &(*encci)[1];
  if ((*enccict) == NULL || (*enccict)[1].type != ASN1_TYPE_OBJECT_IDENTIFIER) {
    printf("ERR: CT EncryptedContent\n"); return 1;
  }
  if ((*enccict)[1].len != 9 || memcmp((*enccict)[1].data, AS2, (*enccict)[1].len) != 0) {
    printf("ERR: CT EncryptedContent PKCS#7\n"); return 1;
  }
  printf("contenttype of encryptedcontentinfo: PKCS#7\n");
  (*ctencalg) = &(*enccict)[1];
  if ((*ctencalg) == NULL) {printf("ERR: EncryptionAlgo\n"); return 1;}
  if ((*ctencalg)[1].type == ASN1_TYPE_SEQUENCE) {
    (*encalgi) = &(*ctencalg)[1];
    if ((*encalgi) == NULL || (*encalgi)[1].type != ASN1_TYPE_OBJECT_IDENTIFIER) {
      printf("ERR: EncryptionAlgoIdentifier\n"); return 1;
    }
    if (memcmp((*encalgi)[1].data, AS3, (*encalgi)[1].len) == 0) {
      printf("content encrypt algo: AES-128-CBC\n");
      (*aesiv) = &(*encalgi)[1];
      if ((*aesiv) == NULL || (*aesiv)[1].type != ASN1_TYPE_OCTET_STRING) {
        printf("ERR: AES IV\n"); return 1;
      }
      printf("AES IV:\n");
      lasn_printhex((*aesiv)[1].data, (*aesiv)[1].len);
    } else {printf("unknown encryption algo\n");}
    (*encct) = &(*ctencalg)[3];
    if ((*encct) == NULL || (*encct)[1].type != 0x80) {
      printf("No encrypted content\n"); return 1;
    }
    printf("Encrypted content:\n");
    lasn_printhex((*encct)[1].data, (*encct)[1].len);
  }
  // this if statement works now, but not 100% sure its correct
  if ((*encci)[2].pos != 0 && (*encci)[2].pos != (*encci)[2].len) {
    printf("unprot attributes avail\n");
  } else printf("no unprot attributes avail\n");
  free((*cms));
  return 0;
}

uint64_t lcrypto_handle_asn_arr(char *cert) {
  char c[2*4096];

  lasn_dump_and_parse_arr((uint8_t*)c, lcrypto_read_cert(cert, c, 1));
  return 1;
}
