//                                                                            //
// Very simple handshake
#ifndef VSH_H
#define VSH_H 1
#include "vsh_defs.h"
#include <sys/socket.h>

key vsh_genkeys(u64 g, u64 p);

u64 vsh_rand();

int vsh_keys();
int vsh_getblock();
int vsh_init(const char *host, const char *port, bool b);
int vsh_listen(int ssock, sock *cli);

void vsh_end(int csock);
void *vsh_handler(void *sdesc);
void vsh_crypt(u64 data, key k, u64 *enc);
void vsh_recvkey(int csock, head *h, key *k);
void vsh_genshare(key *k1, key *k2, u64 p, bool srv);
void vsh_sendkey(int csock, head *h, bool srv, key *k);
void vsh_transferkey(int s, bool snd, bool srv, head *h, key *k);

#endif
