//                                                                            //
// Very simple handshake
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
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
void lcrypto_part_data(u08 d[], int pos, u08 d1[], u08 d2[]) {
  int j = pos;

  for (int i = 0; i < pos; i++) d2[i] = d[i];
  while (d[j] != '\0') {d1[j - pos] = d[j]; j++;}
}

static void lcrypto_asn1node(u08 clas, u08 cons, u08 tag, u08 raw[], u08 no[]) {

}

static void lcrypto_asn1bitstr(u08 bits[1024], u64 rl, u08 ret[1024]) {
  for (u64 i = 1; i < rl; i++) {ret[i - 1] = bits[i];}
}

static void lcrypto_asn1parseoid(u08 bits[], char ret[]) {
  int i = 0, si = 0, subs[1024];

  while (bits[i] != '\0') {
    int cur = 0; cur = (cur << 7) | (bits[i] & 0x7F);
    if (!(bits[i] & 0x80)) {subs[si] = cur; si++;}
    i++;
  }
  int x = 2, y = subs[0] - 80;
  while (y < 0) {x = x - 1; y = y + 40;}
  subs[0] = x; subs[1] = y;
  char s[1024][1024];
  for (i = 0; i < si; i++) {sprintf(s[i], "%d",subs[i]);}
}

// from 390808010001Z to 2039-08-08 01:00:01
static void lcrypto_asn1parsetime(u08 raw[], char ret[19]) {
  ret[0] = '2'; ret[1] = '0';
  ret[2] = raw[0]; ret[3] = raw[1];
  ret[4] = '-'; ret[5] = raw[2]; ret[6] = raw[3];
  ret[7] = '-'; ret[8] = raw[4]; ret[9] = raw[5];
  ret[10] = ' '; ret[11] = raw[6]; ret[12] = raw[7];
  ret[13] = ':'; ret[14] = raw[8]; ret[15] = raw[9];
  ret[16] = ':'; ret[17] = raw[10]; ret[18] = raw[11];
}

// make ret to union!?
static void lcrypto_value(int pos, u08 raw[1024], u64 rl, void* ret) {
  char str[20]; u08 r[1024];

  printf("pos=%d\n", pos);
  if (pos == 1) {if (raw[0] == 0) {memcpy(ret, (void*)0, 1);}
    else {memcpy(ret, (void*)1, 1);}}
  else if (pos == 2) {int r = atoi((char*)raw); ret = &r;}
  else if (pos == 3) {lcrypto_asn1bitstr(raw, rl, r); memcpy(ret, r, rl);}
  else if (pos == 4) {memcpy(ret, raw, rl);}
  else if (pos == 5) {ret = NULL;}
  else if (pos == 6) {lcrypto_asn1parseoid(raw, ret);}
  else if (pos == 12) {memcpy(ret, (char*)raw, 1);}
  else if (pos == 18) {memcpy(ret, (char*)raw, 1);}
  else if (pos == 19) {memcpy(ret, (char*)raw, 1);}
  else if (pos == 20) {memcpy(ret, (char*)raw, 1);}
  else if (pos == 21) {memcpy(ret, (char*)raw, 1);}
  else if (pos == 22) {memcpy(ret, (char*)raw, 4);}
  else if (pos == 23) {lcrypto_asn1parsetime(raw, str); memcpy(ret, str, 1);}
  else if (pos == 24) {lcrypto_asn1parsetime(raw, str); memcpy(ret, str, 1);}
  else if (pos == 28) {memcpy(ret, (char*)raw, 1);}
  else {}
  printf("end...\n");
}

static void lcrypto_headraw(u08 head[], u08 raw[], u64 hl, u64 rl, u08 hr[]) {
  for (u64 i = 0; i < hl; i++) hr[i] = head[i];
  for (u64 i = 0; i < rl; i++) hr[i + hl] = raw[i];
}

static void lcrypto_asn1_decoder(u08 clas, u08 tag, u08 raw[]) {

}

void lcrypto_asn1_handle(u08 d[], u64 l, bool dec) {
  u08 head[1025] = {0}, raw[1025] = {0}, node[1025] = {0}, hr[1025] = {0};
  int co = 0;

  while(d[co] != '\0') {
    u08 llen = 0, clas = d[0] >> 6, cons = d[0] >> 5 & 0x1;
    u08 tag = d[0] & 0x1F, len = d[1];

    if (len & 0x80) {
      llen = len & 0x7F;
      u08 llb = llen + 2;
      char lb[1025] = {0};
      for (int i = 2; i < llb; i++) {lb[i - 2] = d[i]; printf("%d\n", d[i]);}
      printf("atoi: %d\n", atoi(lb));
      len = atoi(lb);
    }
    lcrypto_part_data(d, llen + 2, head, d);
    lcrypto_part_data(d, len, raw, d);
    u64 hl = sizeof(head) / sizeof(u08), rl = sizeof(raw) / sizeof(u08);
    lcrypto_headraw(head, raw, hl, rl, hr);
    lcrypto_asn1node(clas, cons, tag, hr, node);
    printf("%d %d %d %d : %lu, %llu : %d %d\n", raw[0], raw[1], raw[2], raw[3], sizeof(raw), rl, cons, dec);
    if (cons && dec == false) {printf("X\n");printf("decoder recursive\n"); /*lcrypto_asn1_handle(raw, rl, true);*/}
    else if (clas != 0x0 && dec) {printf("Y\n");lcrypto_asn1_decoder(clas, tag, raw);}
    else {printf("Z\n");lcrypto_value(tag, raw, rl, node);}
    co++;
  }
}
