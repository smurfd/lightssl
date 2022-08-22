#ifndef VSH_H
#define VSH_H 1

#include <sys/socket.h>
#include "vsh_defs.h"

//typedef uint64_t u64;

u64 llrand();
void vsh_keys();
void genkeys(u64 g, u64 p, u64 *ret1, u64 *ret2);
void genshare(u64 pub, u64 priv, u64 p, u64 *share);

int vsh_getblock();
int vsh_init(const char *host, const char *port, bool b);
int vsh_listen(int ssock, struct sockaddr *cli);
void vsh_end(int csock);
void vsh_recv(int csock, char *data);
void vsh_send(int csock, const char *msg);
void *vsh_handler(void *sdesc);

#endif
