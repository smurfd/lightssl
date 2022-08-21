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
#include <sys/socket.h>
#include "vsh.h"

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
      printf("Connection error\n"); exit(1);
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
  char (*d) = malloc(BLOCK);
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
      printf("error\n");
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
void genkeys(u64 g, u64 p, u64 *ret1, u64 *ret2) {
  u64 priv = llrand();

  (*ret1) = (u64)pow(g, priv) % p;
  (*ret2) = priv;
}

//
// Generate the shared key
void genshare(u64 pub, u64 priv, u64 p, u64 *share) {
  (*share) = (u64)pow(pub, priv) % p;
}

//
// Generate a keypair & shared key then print it
void vsh_keys() {
  u64 apub1, apriv1, s1, apub2, apriv2, s2, g1, g2, p1, p2;
  srand(time(0));
  g1 = llrand(); g2 = llrand(); p1 = llrand(); p2 = llrand();

  genkeys(g1, p1, &apub1, &apriv1);
  genkeys(g2, p2, &apub2, &apriv2);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", apub1, apriv1);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", apub2, apriv2);
  genshare(apub1, apriv2, p1, &s1);
  genshare(apub2, apriv1, p1, &s2);

  printf("Alice & Bobs Shared secret 0x%.16llx == 0x%.16llx\n", s1, s2);
  assert(s1 == s2);
}
