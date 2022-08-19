#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint64_t llrand();
void keypair();
void genkeys(uint64_t g, uint64_t p, uint64_t *ret1, uint64_t *ret2);
void genshare(uint64_t pub, uint64_t priv, uint64_t p, uint64_t *share);

void vsh_recv(int csock, char *data);
void vsh_send(int csock, const char *msg);
