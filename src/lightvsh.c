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
#include "lightvsh.h"
#include "lightdefs.h"

//
// Initialize server and client (b=true for server deamon)
int vsh_init(const char *host, const char *port, bool b) {
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
void vsh_end(int s) {close(s);}

//
// Server handler
void *vsh_handler(void *sdesc) {
  int s = *(int*)sdesc;
  char (*d) = malloc(vsh_getblock());
  u64 dat[BLOCK], cd[BLOCK];

  if (s == -1) {return (void*)-1;}
  u64 g1 = vsh_rand(), p1 = vsh_rand();
  key k1 = vsh_genkeys(g1, p1), k2;
  k2.publ = 0; k2.priv = 0; k2.shar = 0;
  head h; h.g = g1; h.p = p1;// h.len=11;

  // Send and receive stuff
  if (h.len > BLOCK) {return (void*)-1;}
  vsh_transferkey(s, true, &h, &k1);
  vsh_transferkey(s, false, &h, &k2);
  vsh_genshare(&k1, &k2, h.p, true);
  printf("share : 0x%.16llx %llu %d\n", k2.shar, h.len, s);
  // Decrypt the data
  vsh_transferdata(s, &dat, &h, false, BLOCK-1);
  for (u64 i = 0; i < 10; i++) {vsh_crypt(dat[i], k2, &cd[i]);}
  free(d);
  pthread_exit(NULL);
  return 0;
}

//
// Server listener
int vsh_listen(const int s, sock *cli) {
  int c = 1, *ns, len = sizeof(sock_in);

  listen(s, 3);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    ns = (int*)malloc(sizeof(*ns));
    *ns = c;
    if (pthread_create(&thrd, NULL, vsh_handler, (void*)ns) < 0) {return -1;}
    pthread_join(thrd, NULL);
    free(ns);
  }
  return c;
}

//
// Random uint64_t
u64 vsh_rand() {
  u64 r = 1;

  for (int i = 0; i < 5; ++i) {r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFF;
}

//
// Generate a public and private keypair
key vsh_genkeys(u64 g, u64 p) {
  key k;

  k.priv = vsh_rand();
  k.publ = (int64_t)pow(g, k.priv) % p;
  return k;
}

//
// Generate the shared key
void vsh_genshare(key *k1, key *k2, u64 p, bool srv) {
  if (!srv) {(*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a keypair & shared key then print it (test / demo)
int vsh_keys() {
  u64 g1 = vsh_rand(), g2 = vsh_rand(), p1 = vsh_rand(), p2 = vsh_rand();
  u64 c = 123456, d = 1, e = 1;
  key k1 = vsh_genkeys(g1, p1), k2 = vsh_genkeys(g2, p2);

  vsh_genshare(&k1, &k2, p1, false);
  vsh_genshare(&k1, &k2, p1, true);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  vsh_crypt(c, k1, &d);
  vsh_crypt(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  return c == e;
}

//
// Encrypt and decrypt data with shared key
void vsh_crypt(u64 data, key k, u64 *enc) {(*enc) = data ^ k.shar;}

//
// Get BLOCK size
int vsh_getblock() {return BLOCK;}

//
// Transfer keys (send and receive)
void vsh_transferkey(int s, bool snd, head *h, key *k) {
  key tmp;

  if (snd) {vsh_sendkey(s, h, k);}
  else {vsh_recvkey(s, h, &tmp);
    (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;}
    // This to ensure if we receive a private key we clear it
}

//
// Receive key
void vsh_recvkey(int s, head *h, key *k) {
  recv(s, h, sizeof(head), 0); recv(s, k, sizeof(key), 0); (*k).priv = 0;
  // This to ensure if we receive a private key we clear it
}

//
// Send key
void vsh_sendkey(int s, head *h, key *k) {
  key kk;

  // This to ensure not to send the private key
  kk.publ = (*k).publ; kk.shar = (*k).shar; kk.priv = 0;
  send(s, h, sizeof(head), 0); send(s, &kk, sizeof(key), 0);
}

//
// Transfer data (send and receive)
void vsh_transferdata(const int s, void* data, head *h, bool snd, u64 len) {
  if (snd) {send(s, h, sizeof(head), 0); send(s, data, sizeof(u64) * len, 0);}
  else {recv(s, h, sizeof(head), 0); recv(s, &data, sizeof(u64) * len, 0);}
}
