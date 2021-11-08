//                                                                            //
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>

#ifndef LIGHTSSL_H
#define LIGHTSSL_H

int ls_cli_connect(const char *host, const char *port, bool udp);
void ls_cli_disconnect(int sd, bool udp);
static int ls_srv_wait(int fd);
const char *human_addr(const struct sockaddr *sa, socklen_t salen, char *buf, size_t buflen);
void ls_init();

struct gnutls_session_int;
typedef struct gnutls_session_int *gnutls_session_t;

typedef struct {
  gnutls_session_t session;
  int fd;
  struct sockaddr *cli_addr;
  socklen_t cli_addr_size;
} priv_data_st;

typedef struct {
	unsigned char *data;
	unsigned int size;
} gnutls_datum_t;

typedef struct {
	unsigned int record_seq;
	unsigned int hsk_read_seq;
	unsigned int hsk_write_seq;
} gnutls_dtls_prestate_st;

#define M_BUF 1024

#endif
