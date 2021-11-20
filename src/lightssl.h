//                                                                            //
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "defs.h"

#ifndef LIGHTSSL_H
#define LIGHTSSL_H 1

struct hello {
  bool server;       // is the hello comming from server?
  b08 tls_v;         // 4 = TLS1.3
  u64 rnd;           // random number
  b08 ciph_avail[1]; // available ciphers
  b08 ciph_select[1];// Selected ciphers, will use only SHA512
  b08 compress;      // compression type
  u64 session_id;    // session id
};

struct handshake {
  struct hello hi;

} hs;

void lightssl_print_hello(struct hello *hi);
// Server
int  lightssl_srv_init(const char *host, const char *port);
void *lightssl_srv_handler(void *sdesc);
int  lightssl_srv_listen(int ssock, struct sockaddr *cli);
void lightssl_srv_send(int csock, const char *msg);
void lightssl_srv_recv(int csock, char **data);
// Client
int  lightssl_cli_init(const char *host, const char *port);
void lightssl_cli_send(int csock, const char *msg);
void lightssl_cli_recv(int csock, char **data);
void lightssl_cli_end(int csock);
// Handshake
struct hello* lightssl_hs_set_hello(struct hello *hs, bool srv, int tls,
  u64 r, b08 avail[], b08 sel[], b08 c, u64 sess);
b08 lightssl_hs_send_hi(int csock, bool srv, struct hello *hi);
struct hello* lightssl_hs_recv_hi(int csock, bool srv, struct hello *hi);

#endif

/*
Handshake Start
 C -> ClientHello : tlsversion, randnr, ciphers & compressions, (sessionid)
 S -> ServerHello : tlsversion, randnr, cipher & compression, (sessionid)
 S -> Certificate Message
 S -> ServerKeyExchange Message
 S -> ServerHelloDone : done with negotiating
 C -> ClientKeyExchange Message : PreMasterSecret / public key / null

 C&S use randnr & PreMaster Secret to compute common secret = Master secret
    passed throught pseudorandom()

 C -> ChangeCipherSpec : Now swcure. content type 20?
   [C] -> Finished (authenticated & encrypted) Hash & HMAC of handshake msg
   [S] : Decrypt [C]Finished
       : Verify Hash & HMAC. if not ok, kill connection
 S -> ChangeCipherSpec : Now Secure
   [S] -> Finished (authenticated & encrypted) Hash & HMAC of handshake msg
   [C] : Decrypt [S]Finished
       : Verify Hash & HMAC, if not ok, kill connection

Handshake Done
  ApplicationProtocol enabled, ContentYype=23
  Client/Server exchange is encrypted and authenticated, like Finished.
  otherwise ContentType=25 & no auth

https://datatracker.ietf.org/doc/html/rfc8446
https://en.wikipedia.org/wiki/Transport_Layer_Security
*/

// TODO
// Read: https://dev.to/techschoolguru/a-complete-overview-of-ssl-tls-and-its-cryptographic-system-36pd
// Read: https://dev.to/techschoolguru/how-to-create-sign-ssl-tls-certificates-2aai
