#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "vsh.h"

// gcc vsh_cli.c vsh.c -o cli
// ./cli

//
// Initialize Client
int vsh_cli_init(const char *host, const char *port) {
  int cs, csock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);

  cs = connect(csock, (struct sockaddr *)&saddr, sizeof(saddr));
  if (cs < 0) {
    printf("Connection error\n");
    exit(1);
  }
  return csock;
}

void vsh_cli_end(int csock) { close(csock); }

int main() {
  printf("client connect...\n");
  int c = vsh_cli_init("127.0.0.1", "9998");
  char *cc = malloc(100);
  vsh_send(c, "this is a long string with a very secret message in it, ya digg, brah? or do u digg a whole, fo ya self doodz");
  vsh_recv(c, cc);

  printf("recv: %s\n", cc);
  vsh_cli_end(c);
  free(cc);

  srand(time(0));
  keypair();
}
