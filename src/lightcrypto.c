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
static int lightcrypto_getblock() {return BLOCK;}

//
// Random uint64_t
static u64 lightcrypto_rand() {
  u64 r = 1;

  for (int i = 0; i < 5; ++i) {r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFF;
}

//
// Generate the shared key
void lightcrypto_genshare(key *k1, key *k2, u64 p, bool srv) {
  if (!srv) {(*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a public and private keypair
key lightcrypto_genkeys(u64 g, u64 p) {
  key k;

  k.priv = lightcrypto_rand();
  k.publ = (int64_t)pow(g, k.priv) % p;
  return k;
}

//
// Encrypt and decrypt data with shared key
void lightcrypto_crypt(u64 data, key k, u64 *enc) {(*enc) = data ^ k.shar;}

//
// Receive key
static void lightcrypto_recvkey(int s, head *h, key *k) {
  recv(s, h, sizeof(head), 0); recv(s, k, sizeof(key), 0); (*k).priv = 0;
  // This to ensure if we receive a private key we clear it
}

//
// Send key
static void lightcrypto_sendkey(int s, head *h, key *k) {
  key kk;

  // This to ensure not to send the private key
  kk.publ = (*k).publ; kk.shar = (*k).shar; kk.priv = 0;
  send(s, h, sizeof(head), 0); send(s, &kk, sizeof(key), 0);
}

//
// Transfer data (send and receive)
void lightcrypto_transferdata(const int s, void* data, head *h, bool snd, u64 len) {
  if (snd) {send(s, h, sizeof(head), 0); send(s, data, sizeof(u64) * len, 0);}
  else {recv(s, h, sizeof(head), 0); recv(s, &data, sizeof(u64) * len, 0);}
}

//
// Transfer keys (send and receive)
void lightcrypto_transferkey(int s, bool snd, head *h, key *k) {
  key tmp;

  if (snd) {lightcrypto_sendkey(s, h, k);}
  else {lightcrypto_recvkey(s, h, &tmp);
    (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;}
    // This to ensure if we receive a private key we clear it
}

//
// Server handler
static void *lightcrypto_handler(void *sdesc) {
  u64 dat[lightcrypto_getblock()], cd[lightcrypto_getblock()];
  int s = *(int*)sdesc;

  if (s == -1) {return (void*)-1;}
  u64 g1 = lightcrypto_rand(), p1 = lightcrypto_rand();
  key k1 = lightcrypto_genkeys(g1, p1), k2;
  k2.publ = 0; k2.priv = 0; k2.shar = 0;
  head h; h.g = g1; h.p = p1;

  // Send and receive stuff
  if (h.len > BLOCK) {return (void*)-1;}
  lightcrypto_transferkey(s, true, &h, &k1);
  lightcrypto_transferkey(s, false, &h, &k2);
  lightcrypto_genshare(&k1, &k2, h.p, true);
  printf("share : 0x%.16llx\n", k2.shar);
  // Decrypt the data
  lightcrypto_transferdata(s, &dat, &h, false, BLOCK-1);
  for (u64 i = 0; i < 10; i++) {lightcrypto_crypt(dat[i], k2, &cd[i]);}
  pthread_exit(NULL);
  return 0;
}

//
// Initialize server and client (b=true for server deamon)
int lightcrypto_init(cc *host, cc *port, bool b) {
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
void lightcrypto_end(int s) {close(s);}

//
// Server listener
int lightcrypto_listen(const int s, sock *cli) {
  int c = 1, ns[sizeof(int)], len = sizeof(sock_in);

  listen(s, 3);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    *ns = c;
    if (pthread_create(&thrd, NULL, lightcrypto_handler, (void*)ns) < 0) {
      return -1;
    }
    pthread_join(thrd, NULL);
  }
  return c;
}

//
// Generate a keypair & shared key then print it (test / demo)
int lightcrypto_keys() {
  u64 g1 = lightcrypto_rand(), g2 = lightcrypto_rand(), p1 = lightcrypto_rand();
  u64 p2 = lightcrypto_rand(), c = 123456, d = 1, e = 1;
  key k1 = lightcrypto_genkeys(g1, p1), k2 = lightcrypto_genkeys(g2, p2);

  lightcrypto_genshare(&k1, &k2, p1, false);
  lightcrypto_genshare(&k1, &k2, p1, true);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  lightcrypto_crypt(c, k1, &d);
  lightcrypto_crypt(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  return c == e;
}

// ASN.1
// https://en.wikipedia.org/wiki/ASN.1
// https://www.rfc-editor.org/rfc/rfc6025
// https://www.rfc-editor.org/rfc/rfc5912
static u64 lightcrypto_get_header(u08 c[], u08 h[]) {
  u64 i = 0;

  // Check for the start of -----BEGIN CERTIFICATE-----
  while (c[i] != '-' && c[i + 1] != '-' && c[i + 2] != '-' && c[i + 3] != '-'\
    && c[i + 4] != '-' && c[i + 5] != 'B') {i++;}
  while (c[i] != '\n') {
    h[i] = c[i];
    i++;
  }
  h[i] = '\0';
  return i;
}

static u64 lightcrypto_get_footer(u08 c[], u64 len, u08 f[]) {
  u64 i = 0, j = len - 36;

  // check for the start of -----END CERTIFICATE-----
  while (c[j] != '\n') {j++;}
  while (c[j] != '-' && c[j + 1] != '-' && c[j + 2] != '-' && c[j + 3] != '-'\
    && c[j + 4] != '-' && c[j + 5] != 'E') {j++;}
  j++;
  while (c[j] != '\n') {
    f[i] = c[j];
    i++; j++;
  }
  f[i] = '\0';
  return i;
}

static u64 lightcrypto_get_data(u08 c[], u64 h, u64 f, u64 l, u08 d[]) {
  u64 co = l - f - h - 3, i = 0;

  while (i < co) {d[i] = c[h + i + 1]; i++;}
  d[i - 1] = '\0';
  return i;
}

static u64 lightcrypto_read_cert(char *fn, u08 c[]) {
  u64 len = 0;
  char ch = '\0';
  FILE* ptr;

  ptr = fopen(fn, "r");
  if (NULL == ptr) {printf("Can't find cert\n");}
  while (ch != EOF) {
    ch = fgetc(ptr);
    c[len] = ch;
    len++;
  }
  fclose(ptr);
  return len;
}

u64 lightcrypto_handle_cert(char *cert) {
  u64 len = 0, foot, head, data;
  u08 crt[2048], h[36], f[36], d[2048];

  len = lightcrypto_read_cert(cert, crt);
  printf("length %llu\n", len);
  head = lightcrypto_get_header(crt, h);
  printf("Header: %s\n", h);
  foot = lightcrypto_get_footer(crt, len, f);
  printf("Footer: %s\n", f);
  data = lightcrypto_get_data(crt, head, foot, len, d);
  printf("Data: %s\n", d);
  return data;
}

static int mod_table[] = {0, 2, 1};
static char enc[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3','4', '5', '6', '7', '8', '9', '+', '/'};

static u32 octet(int i, int inl, const unsigned char d[257]) {
  if (i < inl) {return d[i];} else {return 0;}
}

static u32 sextet(const char d[257], char c[257], int i) {
  if (d[i] == '=') {return 0 & i++;} else {return c[(int)d[i]];}
}

void lightcrypto_encode64(const unsigned char *data, int inl, int *outl, char encd[*outl]) {
  *outl = 4 * ((inl + 2) / 3);
  for (int i = 0, j = 0; i < inl;) {
    u32 a = octet(i++, inl, data);
    u32 b = octet(i++, inl, data);
    u32 c = octet(i++, inl, data);
    u32 triple = (a << 0x10) + (b << 0x08) + c;

    encd[j++] = enc[(triple >> 3 * 6) & 0x3F];
    encd[j++] = enc[(triple >> 2 * 6) & 0x3F];
    encd[j++] = enc[(triple >> 1 * 6) & 0x3F];
    encd[j++] = enc[(triple >> 0 * 6) & 0x3F];
  }
  for (int i = 0; i < mod_table[inl % 3]; i++) encd[*outl - 1 - i] = '=';
}

void lightcrypto_decode64(const char *data, int inl, int *outl, unsigned char decd[*outl]) {
  static char dec[257] = {0};

  *outl = inl / 4 * 3;
  if (data[inl - 1] == '=') (*outl)--;
  if (data[inl - 2] == '=') (*outl)--;
  for (int i = 0; i < 64; i++) dec[(unsigned char) enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    u32 a = sextet(data, dec, i++);
    u32 b = sextet(data, dec, i++);
    u32 c = sextet(data, dec, i++);
    u32 d = sextet(data, dec, i++);
    u32 triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

    if (j < *outl) decd[j++] = (triple >> 2 * 8) & 0xFF;
    if (j < *outl) decd[j++] = (triple >> 1 * 8) & 0xFF;
    if (j < *outl) decd[j++] = (triple >> 0 * 8) & 0xFF;
  }
}
