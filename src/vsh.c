#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//
// Client receive message
void vsh_recv(int csock, char *data) {
  uint64_t len;
  recv(csock, &len, sizeof(uint64_t), 0);
  recv(csock, data, ntohl(len), 0);
}

//
// Client send message
void vsh_send(int csock, const char *msg) {
  uint64_t len = strlen(msg);
  send(csock, &len, sizeof(uint64_t), 0);
  send(csock, msg, len, 0);
}

uint64_t llrand() {
  uint64_t r = 0;
  for (int i = 0; i < 5; ++i) { r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFFULL;
}

void genkeys(uint64_t g, uint64_t p, uint64_t *ret1, uint64_t *ret2) {
  uint64_t priv = llrand();

  (*ret1) = (uint64_t)pow(g, priv) % p;
  (*ret2) = priv;
}

void genshare(uint64_t pub, uint64_t priv, uint64_t p, uint64_t *share) {
  (*share) = (uint64_t)pow(pub, priv) % p;
}

void keypair() {
  uint64_t g1 = llrand(), p1 = llrand(), g2 = llrand(), p2 = llrand();
  uint64_t apub1, apriv1, s1, apub2, apriv2, s2;

  genkeys(g1, p1, &apub1, &apriv1);
  genkeys(g2, p2, &apub2, &apriv2);
  printf("0x%.16llx 0x%.16llx : 0x%.16llx 0x%.16llx\n", apub1, apriv1, g1, p1);
  printf("0x%.16llx 0x%.16llx : 0x%.16llx 0x%.16llx\n", apub2, apriv2, g2, p2);
  genshare(apub1, apriv2, p1, &s1);
  genshare(apub2, apriv1, p1, &s2);

  printf("Share 0x%.16llx == 0x%.16llx\n", s1, s2);
}
