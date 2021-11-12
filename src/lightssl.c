//                                                                            //
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "lightssl.h"

// dummy
void ls_init() {
  printf("hi from lib\n");
}

int ls_srv_init(const char *host, const char *port) {
  int ssock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  memset(&saddr, '\0', sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);

  bind(ssock, (struct sockaddr*)&saddr, sizeof(saddr));
  return ssock;
}

void *ls_srv_handler(void *sdesc) {
  int s = *(int*)sdesc;
  int rd = 1;
  char *msg;
  char cm[2000];

  while (rd) {
    rd = recv(s, cm, 2000, 0);
    write(s, cm, strlen(cm));
    printf("cm = %s\n", cm);
    memset(cm, '\0', 2000);
  }
  // if rd == 0, client disconnect
  // if rd < 0, received failed

  free(sdesc);
  close(s);
  pthread_exit(NULL);
  return 0;
}

int ls_srv_listen(int ssock, struct sockaddr *cli) {
  int csock = 1;
  int *new_sock;
  int c = sizeof(struct sockaddr_in);
  listen(ssock, 3);
  while(csock) {
    csock = accept(ssock, (struct sockaddr*)&cli, (socklen_t*)&c);
    pthread_t sniffer_thread;
    new_sock = (int*)malloc(sizeof *new_sock);
    *new_sock = csock;
    if (pthread_create(&sniffer_thread, NULL, ls_srv_handler, (void*)new_sock) < 0) {
      // couldnt create thread
      return 1;
    }
  }
  return csock;
}

void ls_srv_send(int csock, const char *msg) {
  send(csock, msg, sizeof(msg), 0);
}

int ls_cli_init(const char *host, const char *port) {
  int csock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);

  int cs = connect(csock, (struct sockaddr*)&saddr, sizeof(saddr));
  if (cs < 0) {
    printf("Connection error\n");
    exit(1);
  }
  return csock;
}

char* ls_cli_recv(int csock, char *data) {
  recv(csock, data, sizeof(data), 0);
  return data;
}

void ls_cli_send(int csock, const char *msg) {
  send(csock, msg, strlen(msg), 0);
}
// Example:
// Server
// int s = ls_srv_init("127.0.0.1", "12345");
// int c = ls_srv_listen(s);
// ls_srv_send(c, "hey");
//
// Client
// char *data;
// data = (char*) malloc(1024);
// int c = ls_cli_init("127.0.0.1", "12345");
// printf("Rec from server: %s\n", ls_cli_recv(c));
