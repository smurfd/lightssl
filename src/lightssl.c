//                                                                            //
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

int ls_srv_listen(int ssock) {
  listen(ssock, 1);
  int csock = accept(ssock, NULL, NULL);
  return csock;
}

void ls_srv_send(int csock, const char* msg) {
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

char* ls_cli_recv(int csock, char* data) {
  recv(csock, data, sizeof(data), 0);
  return data;
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
