//                                                                            //
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "defs.h"

#ifndef LIGHTSSL_H
#define LIGHTSSL_H 1

void ls_init();
// Server
int ls_srv_init(const char *host, const char *port);
void *ls_srv_handler(void *sdesc);
int ls_srv_listen(int ssock, struct sockaddr *cli);
void ls_srv_send(int csock, const char *msg);
// Client
int ls_cli_init(const char *host, const char *port);
void ls_cli_send(int csock, const char *msg);
char* ls_cli_recv(int csock, char *data);

#endif
