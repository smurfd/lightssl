#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>

//
// Receive message
void vsh_recv(int csock, char *data) {
  uint64_t len;
  recv(csock, &len, sizeof(uint64_t), 0);
  recv(csock, data, ntohl(len), 0);
}

//
// Send message
void vsh_send(int csock, const char *msg) {
  uint64_t len = strlen(msg);
  send(csock, &len, sizeof(uint64_t), 0);
  send(csock, msg, len, 0);
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
  char (*d) = malloc(100);
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
uint64_t llrand() {
  uint64_t r = 0;
  for (int i = 0; i < 5; ++i) { r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFFULL;
}

//
// Generate a public and private keypair
void genkeys(uint64_t g, uint64_t p, uint64_t *ret1, uint64_t *ret2) {
  uint64_t priv = llrand();

  (*ret1) = (uint64_t)pow(g, priv) % p;
  (*ret2) = priv;
}

//
// Generate the shared key
void genshare(uint64_t pub, uint64_t priv, uint64_t p, uint64_t *share) {
  (*share) = (uint64_t)pow(pub, priv) % p;
}

//
// Generate a keypair & shared key then print it
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
