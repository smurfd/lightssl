#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "vsh.h"

// gcc vsh_srv.c vsh.c -o srv
// ./srv

//
// Server handler
void *vsh_srv_handler(void *sdesc) {
  int s = *(int *)sdesc;
  char (*d) = malloc(100);
  if (s == -1) {
    return (void *)-1;
  }
  // Send and receive stuff
  vsh_recv(s, d);
  vsh_send(s, "zdood fles ay of ,elohw a ggid u od ro ?harb ,ggid ay ,ti ni egassem terces yrev a htiw gnirts gnol a si siht");

  free(d);
  pthread_exit(NULL);
  return 0;
}

//
// Initialize server
int vsh_srv_init(const char *host, const char *port) {
  int ssock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  memset(&saddr, '\0', sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);

  bind(ssock, (struct sockaddr *)&saddr, sizeof(saddr));
  return ssock;
}

// Server listener
int vsh_srv_listen(int ssock, struct sockaddr *cli) {
  int csock = 1, *new_sock, c = sizeof(struct sockaddr_in);

  listen(ssock, 3);
  while (csock >= 1) {
    csock = accept(ssock, (struct sockaddr *)&cli, (socklen_t *)&c);
    pthread_t sniffer_thread;
    new_sock = (int *)malloc(sizeof *new_sock);
    *new_sock = csock;
    if (pthread_create(
          &sniffer_thread, NULL, vsh_srv_handler, (void *)new_sock) < 0) {
      printf("error\n");
      return -1;
    }
    pthread_join(sniffer_thread, NULL);
  }
  return csock;
}


int main() {
  struct sockaddr *cli = NULL;
  printf("server listening\n");
  int s = vsh_srv_init("127.0.0.1", "9998");
  vsh_srv_listen(s, cli);
  close(s);
}