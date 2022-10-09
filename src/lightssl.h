//                                                                            //
#ifndef LIGHTSSL_H
#define LIGHTSSL_H 1

#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "lightdefs.h"

struct hello {
  bool server;                                   // Is hello comming from server
  b08 tls_v;                                     // 4 = TLS1.3
  u64 rnd;                                       // Random number
  b08 ciph_avail[1];                             // Available ciphers
  b08 ciph_select[1];                            // Selected ciphers, SHA512
  b08 compress;                                  // Compression type
  u64 session_id;                                // Session id
};

void lightssl_print_hello(struct hello *hi);

// Server
void *lightssl_srv_handler(void *sdesc);
void lightssl_srv_recv(int csock, char **data);
void lightssl_srv_send(int csock, const char *msg);
int lightssl_srv_listen(int ssock, struct sockaddr *cli);
int lightssl_srv_init(const char *host, const char *port);

// Client
void lightssl_cli_end(int csock);
void lightssl_cli_recv(int csock, char **data);
void lightssl_cli_send(int csock, const char *msg);
int lightssl_cli_init(const char *host, const char *port);

// Handshake
struct hello *lightssl_hs_set_hello(struct hello *hs, bool srv, int tls, u64 r,
  b08 avail[], b08 sel[], b08 c, u64 sess);
b08 lightssl_hs_send_hi(int csock, bool srv, struct hello *hi);
struct hello *lightssl_hs_recv_hi(int csock, bool srv, struct hello *hi);
#endif
// https://datatracker.ietf.org/doc/html/rfc8446
// https://en.wikipedia.org/wiki/Transport_Layer_Security
// https://dev.to/techschoolguru/a-complete-overview-of-ssl-tls-and-its-cryptographic-system-36pd
// https://dev.to/techschoolguru/how-to-create-sign-ssl-tls-certificates-2aai
