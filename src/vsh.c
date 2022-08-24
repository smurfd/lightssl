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
// Receive message
void vsh_recv(int csock, char *data) {
  struct header h;
  recv(csock, &h, sizeof(header), 0);
  recv(csock, data, ntohl(h.len), 0);
}

//
// Send message
void vsh_send(int csock, const char *msg) {
  header.len = strlen(msg);
  send(csock, &header, sizeof(header), 0);
  send(csock, msg, header.len, 0);
}

//
// Initialize server and client (b=true for server deamon)
int vsh_init(const char *host, const char *port, bool b) {
  int ssock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  memset(&saddr, '\0', sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);
  if (b == true) {
    bind(ssock, (struct sockaddr *)&saddr, sizeof(saddr));
  } else {
    if (connect(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      printf("Connection error\n"); return -1;
    }
  }
  return ssock;
}

//
// End connection
void vsh_end(int csock) {close(csock);}

//
// Server handler
void *vsh_handler(void *sdesc) {
  int s = *(int *)sdesc;
  char (*d) = malloc(vsh_getblock());
  if (s == -1) {
    return (void *)-1;
  }
  // Send and receive stuff
  vsh_recv(s, d);
  vsh_send(s, "zdood gnirts gnol a si siht");

  free(d);
  pthread_exit(NULL);
  return 0;
}

//
// Server listener
int vsh_listen(int ssock, struct sockaddr *cli) {
  int csock = 1, *newsock, c = sizeof(struct sockaddr_in);

  listen(ssock, 3);
  while (csock >= 1) {
    csock = accept(ssock, (struct sockaddr *)&cli, (socklen_t *)&c);
    pthread_t thrd;
    newsock = (int *)malloc(sizeof *newsock);
    *newsock = csock;
    if (pthread_create(&thrd, NULL, vsh_handler, (void *)newsock) < 0) {
      return -1;
    }
    pthread_join(thrd, NULL);
    free(newsock);
  }
  return csock;
}

//
// Random uint64_t
u64 llrand() {
  u64 r = 0;
  for (int i = 0; i < 5; ++i) { r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFFULL;
}

//
// Generate a public and private keypair
struct keys genkeys(u64 g, u64 p) {
  struct keys k;
  k.priv = llrand();
  k.publ = (u64)pow(g, k.priv) % p;
  return k;
}

//
// Generate the shared key
u64 genshare(struct keys *k1, struct keys *k2, u64 p) {
  (*k1).shar = p % (u64)pow((*k1).publ, (*k2).priv);
  (*k2).shar = p % (u64)pow((*k2).publ, (*k1).priv);
  assert((*k1).shar == (*k2).shar);
  if ((*k1).shar == (*k2).shar) return (*k1).shar;
  else return 0;
}

//
// Generate a keypair & shared key then print it
void vsh_keys() {
  u64 g1 = llrand(), g2 = llrand(), p1 = llrand(), p2 = llrand();

  struct keys k1 = genkeys(g1, p1), k2 = genkeys(g1, p2);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  genshare(&k1, &k2, p1);
  printf("Alice and Bobs shared keys: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
}

//
// Get BLOCK size
int vsh_getblock() {return BLOCK;}
