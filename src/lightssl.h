//                                                                            //
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "defs.h"

#ifndef LIGHTSSL_H
#define LIGHTSSL_H 1

void ls_init();
int ls_srv_init(const char *host, const char *port);
int ls_srv_listen(int ssock);
void ls_srv_send(int csock, const char* msg);

int ls_cli_init(const char *host, const char *port);
char* ls_cli_recv(int csock, char *data);

#endif
