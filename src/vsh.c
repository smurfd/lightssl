//                                                                            //
// Very simple handshake
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "vsh.h"
#include "vsh_defs.h"

//
// Initialize server and client (b=true for server deamon)
int vsh_init(const char *host, const char *port, bool b) {
  int ssock = socket(AF_INET, SOCK_STREAM, 0);
  sock_in saddr;

  memset(&saddr, '\0', sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);
  if (b == true) {bind(ssock, (sock*)&saddr, sizeof(saddr));}
  else {if (connect(ssock, (sock*)&saddr, sizeof(saddr)) < 0) {
    printf("Connection error\n"); return -1;}}
  return ssock;
}

//
// End connection
void vsh_end(int csock) {close(csock);}

//
// Server handler
void *vsh_handler(void *sdesc) {
  int s = *(int*)sdesc;
  char (*d) = malloc(vsh_getblock());

  if (s == -1) {return (void*)-1;}
  // Send and receive stuff
  u64 g1 = vsh_rand(), p1 = vsh_rand();
  key k1 = vsh_genkeys(g1, p1), k2;
  head h; h.g = g1; h.p = p1;
  k2.publ = 0; k2.priv = 0; k2.shar = 0;
  vsh_transferkey(s, true, true, &h, &k1);
  vsh_transferkey(s, false, true, &h, &k2);
  vsh_genshare(&k1, &k2, h.p, true);
  printf("share : 0x%.16llx\n", k2.shar);
  free(d);
  pthread_exit(NULL);
  return 0;
}

//
// Server listener
int vsh_listen(int ssock, sock *cli) {
  int csock = 1, *newsock, c = sizeof(sock_in);

  listen(ssock, 3);
  while (csock >= 1) {
    csock = accept(ssock, (sock*)&cli, (socklen_t*)&c);
    pthread_t thrd;
    newsock = (int*)malloc(sizeof(*newsock));
    *newsock = csock;
    if (pthread_create(&thrd, NULL, vsh_handler, (void*)newsock) < 0) {
      return -1;
    }
    pthread_join(thrd, NULL);
    free(newsock);
  }
  return csock;
}

//
// Random uint64_t
u64 vsh_rand() {
  u64 r = 0;

  for (int i = 0; i < 5; ++i) { r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFFULL;
}

//
// Generate a public and private keypair
key vsh_genkeys(u64 g, u64 p) {
  key k;

  k.priv = vsh_rand();
  k.publ = (u64)pow(g, k.priv) % p;
  return k;
}

//
// Generate the shared key
void vsh_genshare(key *k1, key *k2, u64 p, bool srv) {
  if (!srv) {(*k1).shar = p % (u64)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (u64)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a keypair & shared key then print it (test / demo)
int vsh_keys() {
  u64 g1 = vsh_rand(), g2 = vsh_rand(), p1 = vsh_rand(), p2 = vsh_rand();
  u64 c = 123456, d = 0, e = 0;
  key k1 = vsh_genkeys(g1, p1), k2 = vsh_genkeys(g1, p2);

  vsh_genshare(&k1, &k2, p1, false);
  vsh_genshare(&k1, &k2, p1, true);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);

  vsh_crypt(c, k1, &d);
  vsh_crypt(d, k2, &e);
  printf("Before: 0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n", c, d, e);
  assert(c == e);
  return c == e;
}

//
// Encrypt and decrypt data with shared key
void vsh_crypt(u64 data, key k, u64 *enc) {(*enc) = data ^ k.shar;}

//
// Get BLOCK size
int vsh_getblock() {return BLOCK;}

void vsh_transferkey(int s, bool snd, bool srv, head *h, key *k) {
  key tmp;

  if (snd) {vsh_sendkey(s, h, srv, k);}
  else {vsh_recvkey(s, h, &tmp);
    (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;}
    // This to ensure if we receive a private key we clear it
}

void vsh_recvkey(int csock, head *h, key *k) {
  recv(csock, h, sizeof(head), 0);
  recv(csock, k, sizeof(key), 0);
  (*k).priv = 0;
}

void vsh_sendkey(int csock, head *h, bool srv, key *k) {
  key kk;

  kk.publ = (*k).publ;
  kk.priv = 0; // This to ensure not to send the private key
  kk.shar = (*k).shar;

  send(csock, h, sizeof(head), 0);
  send(csock, &kk, sizeof(key), 0);
}
