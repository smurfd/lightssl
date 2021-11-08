//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include "lightssl.h"

// Client connect
int ls_cli_connect(const char *host, const char *port, bool udp) {
  int err, sd;
  struct sockaddr_in sa;
  if (udp == true) {
    sd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sd = socket(AF_INET, SOCK_STREAM, 0);
  }

  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(atoi(port));
  inet_pton(AF_INET, host, &sa.sin_addr);

  err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
  if (err < 0) {
    fprintf(stderr, "Connection error\n");
    exit(1);
  }
  return sd;
}

// Client disconnect
void ls_cli_disconnect(int sd, bool udp) {
  if (udp == false) {
    shutdown(sd, SHUT_RDWR);
  }
  close(sd);
}

// Server
int ls_srv_server(const char *host, const char *port, bool udp) {
  int listen_sd;
  int sock, ret;
  struct sockaddr_in sa_serv;
  struct sockaddr_in cli_addr;
  socklen_t cli_addr_size;
  gnutls_session_t session;
  char buffer[M_BUF];
  priv_data_st priv;
  gnutls_datum_t cookie_key;
  gnutls_dtls_prestate_st prestate;
  int mtu = 1400;
  unsigned char sequence[8];
/*
  gnutls_global_init();

  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,GNUTLS_X509_FMT_PEM);
  gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,GNUTLS_X509_FMT_PEM);

  ret = gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE,KEYFILE,GNUTLS_X509_FMT_PEM);
  if (ret < 0) {
    printf("No certificate or key were found\n");
    exit(1);
  }

  gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);
  gnutls_priority_init2(&priority_cache,"%SERVER_PRECEDENCE",NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);

  gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);
*/
  listen_sd = socket(AF_INET, SOCK_DGRAM, 0);

  memset(&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port = htons(atoi(port));

  bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
  printf("UDP server ready. Listening to port '%d'.\n\n", atoi(port));

  for (;;) {
    printf("Waiting for connection...\n");
    sock = ls_srv_wait(listen_sd);
    if (sock < 0) {
      continue;
    }

    cli_addr_size = sizeof(cli_addr);
    ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK,
      (struct sockaddr *) &cli_addr,&cli_addr_size);

    if (ret > 0) {
      memset(&prestate, 0, sizeof(prestate));
//      ret = gnutls_dtls_cookie_verify(&cookie_key,&cli_addr,
//        sizeof(cli_addr), buffer, ret, &prestate);
      if (ret < 0) { // bad cookies
        priv_data_st s;

        memset(&s, 0, sizeof(s));
        s.fd = sock;
        s.cli_addr = (void *) &cli_addr;
        s.cli_addr_size = sizeof(cli_addr);

        printf("Sending hello verify request to %s\n",
          human_addr((struct sockaddr *) &cli_addr,
          sizeof(cli_addr), buffer,sizeof(buffer)));

//        gnutls_dtls_cookie_send(&cookie_key, &cli_addr,
//          sizeof(cli_addr), &prestate, (gnutls_transport_ptr_t) & s, push_func);

        recvfrom(sock, buffer, sizeof(buffer), 0,
          (struct sockaddr *) &cli_addr, &cli_addr_size);
        usleep(100);
        continue;
      }

      printf("Accepted connection from %s\n",
        human_addr((struct sockaddr *)
        &cli_addr, sizeof(cli_addr), buffer, sizeof(buffer)));
    } else {
      continue;
    }
/*
    gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
    gnutls_priority_set(session, priority_cache);
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

    gnutls_dtls_prestate_set(session, &prestate);
    gnutls_dtls_set_mtu(session, mtu);
*/
    priv.session = session;
    priv.fd = sock;
    priv.cli_addr = (struct sockaddr *) &cli_addr;
    priv.cli_addr_size = sizeof(cli_addr);
/*
    gnutls_transport_set_ptr(session, &priv);
    gnutls_transport_set_push_function(session, push_func);
    gnutls_transport_set_pull_function(session, pull_func);
    gnutls_transport_set_pull_timeout_function(session, pull_timeout_func);

    LOOP_CHECK(ret, gnutls_handshake(session));
*/
    if (ret < 0) {
//      fprintf(stderr, "Error in handshake(): %s\n", gnutls_strerror(ret));
//      gnutls_deinit(session);
      continue;
    }

    printf("- Handshake was completed\n");
    for (;;) {
//      LOOP_CHECK(ret, gnutls_record_recv_seq(session, buffer, M_BUF, sequence));
      if (ret < 0 ) {//&& gnutls_error_is_fatal(ret) == 0) {
//        fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
        continue;
      } else if (ret < 0) {
//        fprintf(stderr, "Error in recv(): %s\n", gnutls_strerror(ret));
        break;
      }

      if (ret == 0) {
        printf("EOF\n\n");
        break;
      }

      buffer[ret] = 0;
      printf("received[%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x]: %s\n",
        sequence[0], sequence[1], sequence[2],
        sequence[3], sequence[4], sequence[5],
        sequence[6], sequence[7], buffer);

//      LOOP_CHECK(ret, gnutls_record_send(session, buffer, ret));
      if (ret < 0) {
//        fprintf(stderr, "Error in send(): %s\n", gnutls_strerror(ret));
        break;
      }
    }

//    LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));
//    gnutls_deinit(session);
  }

  close(listen_sd);
/*
  gnutls_certificate_free_credentials(x509_cred);
  gnutls_priority_deinit(priority_cache);
  gnutls_global_deinit();
*/
  return 0;
}

const char *human_addr(const struct sockaddr *sa, socklen_t salen, char *buf, size_t buflen) {
  const char *save_buf = buf;
  size_t l;

  if (!buf || !buflen) {
    return "(error)";
  }

  *buf = 0;
  switch (sa->sa_family) {
    case AF_INET:
      snprintf(buf, buflen, "IPv4 ");
      break;
  }

  l = 5;
  buf += l;
  buflen -= l;

  if (getnameinfo(sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) != 0) {
    return "(error)";
  }

  l = strlen(buf);
  buf += l;
  buflen -= l;

  if (buflen < 8) {
    return save_buf;
  }

  strcat(buf, " port ");
  buf += 6;
  buflen -= 6;

  if (getnameinfo(sa, salen, NULL, 0, buf, buflen, NI_NUMERICSERV) != 0) {
  snprintf(buf, buflen, "%s", " unknown");
  }

  return save_buf;
}

// Server await connection
static int ls_srv_wait(int fd) {
  fd_set rd, wr;
  int n;

  FD_ZERO(&rd);
  FD_ZERO(&wr);

  FD_SET(fd, &rd);

  n = select(fd + 1, &rd, &wr, NULL, NULL);
  if (n == -1 && errno == EINTR) {
    return -1;
  }
  if (n < 0) {
    perror("select()");
    exit(1);
  }

  return fd;
}
// dummy
void ls_init() {
  printf("hi from lib\n");
}
