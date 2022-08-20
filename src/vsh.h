#ifndef VSH_H
#define VSH_H 1

struct sockaddr;

uint64_t llrand();
void keypair();
void genkeys(uint64_t g, uint64_t p, uint64_t *ret1, uint64_t *ret2);
void genshare(uint64_t pub, uint64_t priv, uint64_t p, uint64_t *share);

void vsh_recv(int csock, char *data);
void vsh_send(int csock, const char *msg);
void vsh_end(int csock);
void *vsh_handler(void *sdesc);
int vsh_init(const char *host, const char *port, bool b);
int vsh_listen(int ssock, struct sockaddr *cli);

#endif
