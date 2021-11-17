//                                                                            //
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "lightssl.h"

// TODO: rework variable names to differ from functionnames
// TODO: rework listen server loop
void lightssl_print_hello(struct hello *hi) {
  printf("Hello: %d %d %llu %d %d %d %llu\n",
    hi->server, hi->tls_v, hi->rnd, hi->ciph_avail[0],
    hi->ciph_select[0], hi->compress, hi->session_id);
}

int lightssl_srv_init(const char *host, const char *port) {
  int ssock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  memset(&saddr, '\0', sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);

  bind(ssock, (struct sockaddr*)&saddr, sizeof(saddr));
  return ssock;
}

void *lightssl_srv_handler(void *sdesc) {
  int s = *(int*)sdesc;
  b08 avail[] = {TLSCIPHER};
  b08 select[] = {TLSCIPHERAVAIL};
  b08 compress = TLSCOMPRESSION;
  struct hello *hs_srv;
  struct hello *hs_cli_recv;

  if (s==-1) {
    return (void*)-1;
  }

  hs_srv = (struct hello*) malloc(sizeof(struct hello));
  hs_cli_recv = (struct hello*) malloc(sizeof(struct hello));
  lightssl_hs_set_hello(hs_srv, true, TLSVERSION, 1337, avail, select,
    compress, 13371337);
  lightssl_hs_send_hi(s, true, hs_srv);
  lightssl_hs_recv_hi(s, true, hs_cli_recv);
  lightssl_print_hello(hs_cli_recv);
  free(hs_cli_recv);
  free(hs_srv);
  free(sdesc);
  close(s);
  pthread_exit(NULL);
  return 0;
}

int lightssl_srv_listen(int ssock, struct sockaddr *cli) {
  int csock = 1;
  int *new_sock;
  int c = sizeof(struct sockaddr_in);
  listen(ssock, 3);
  while(csock >= 1) {
    csock = accept(ssock, (struct sockaddr*)&cli, (socklen_t*)&c);
    pthread_t sniffer_thread;
    new_sock = (int*)malloc(sizeof *new_sock);
    *new_sock = csock;
    if (pthread_create(&sniffer_thread, NULL, lightssl_srv_handler, (void*)new_sock) < 0) {
      printf("error\n");
      return -1;
    }
    pthread_join(sniffer_thread, NULL);
  }
  return csock;
}

void lightssl_srv_send(int csock, const char *msg) {
  send(csock, msg, strlen(msg), 0);
}

void lightssl_srv_recv(int csock, char **data) {
  recv(csock, &data, sizeof(data), 0);
}

int lightssl_cli_init(const char *host, const char *port) {
  int csock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in saddr;

  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(port));
  saddr.sin_addr.s_addr = inet_addr(host);

  int cs = connect(csock, (struct sockaddr*)&saddr, sizeof(saddr));
  if (cs < 0) {
    printf("Connection error\n");
    exit(1);
  }
  return csock;
}

void lightssl_cli_recv(int csock, char **data) {
  recv(csock, data, sizeof(data), 0);
}

void lightssl_cli_send(int csock, const char *msg) {
  send(csock, msg, strlen(msg), 0);
}

void lightssl_cli_end(int csock) {
  close(csock);
}

struct hello* lightssl_hs_set_hello(struct hello *hi, bool srv, b08 tls,
  u64 r, b08 avail[], b08 sel[], b08 c, u64 sess) {
  hi->server = srv;
  hi->tls_v = tls; // will be 4 = TLS1.3
  hi->rnd = r;
  hi->ciph_avail[0] = avail[0]; // will only use 1 cipher
  hi->ciph_select[0] = sel[0]; // will only use 1 cipher
  hi->compress = c;
  hi->session_id = sess;
  return hi;
}

b08 lightssl_hs_send_hi(int csock, bool srv, struct hello *hi) {
  if (srv) {
    printf("Sending Hello from server\n");
  } else {
    printf("Sending Hello from client\n");
  }

  send(csock, hi, sizeof(struct hello), 0);
  lightssl_print_hello(hi);
  return 0;
}

struct hello* lightssl_hs_recv_hi(int csock, bool srv, struct hello *hi) {
  int r, r_tot;
  if (srv) {
    printf("Receiving Hello from client\n");
  } else {
    printf("Receiving Hello from server\n");
  }
  r_tot = 0;
  r = 0;
  while((u64)r_tot < sizeof(struct hello)) {
    r = recv(csock, hi, sizeof(struct hello), 0);
    if(r==-1) break;
    if (r>0) {
      r_tot = r_tot + r;
    }
  }
  return hi;
}
