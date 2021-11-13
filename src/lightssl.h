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
#endif
