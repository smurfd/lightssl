#ifndef VSH_H
#define VSH_H 1

#include <sys/socket.h>

typedef uint64_t u64;
struct keys {
  uint64_t publ;
  uint64_t priv;
  uint64_t shar;
} keys;

u64 llrand();
void vsh_keys();
struct keys genkeys(u64 g, u64 p);
u64 genshare(struct keys *k1, struct keys *k2, u64 p);

int vsh_getblock();
int vsh_init(const char *host, const char *port, bool b);
int vsh_listen(int ssock, struct sockaddr *cli);
void vsh_end(int csock);
void vsh_recv(int csock, char *data);
void vsh_send(int csock, const char *msg);
void *vsh_handler(void *sdesc);

#endif