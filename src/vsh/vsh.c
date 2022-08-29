//                                                                            //
// Very simple handshake
#include "vsh.h"
#include "vsh_defs.h"

//
// Initialize server and client (b=true for server deamon)
int vsh_init(const char *host, const char *port, bool b) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  sock_in adr;

  memset(&adr, '\0', sizeof(adr));
  adr.sin_family = AF_INET;
  adr.sin_port = atoi(port);
  adr.sin_addr.s_addr = inet_addr(host);
  if (b == true) {bind(s, (sock*)&adr, sizeof(adr));}
  else {if (connect(s, (sock*)&adr, sizeof(adr)) < 0) {return -1;}}
  return s;
}

//
// End connection
void vsh_end(int s) {close(s);}

//
// Server handler
void *vsh_handler(void *sdesc) {
  u64 g1 = vsh_rand(), p1 = vsh_rand();
  char (*d) = malloc(vsh_getblock());
  key k1 = vsh_genkeys(g1, p1), k2;
  u64 dat[BLOCK], cd[BLOCK];
  head h; h.g = g1; h.p = p1;
  int s = *(int*)sdesc;

  // Send and receive stuff
  if (s == -1) {return (void*)-1;}
  if (h.len > BLOCK) {return (void*)-1;}

  k2.publ = 0; k2.priv = 0; k2.shar = 0;
  vsh_transferkey(s, true, &h, &k1);
  vsh_transferkey(s, false, &h, &k2);
  vsh_genshare(&k1, &k2, h.p, true);
  printf("share : 0x%.16llx\n", k2.shar);

  vsh_transferdata(s, &dat, false, h.len);
  // Decrypt the data
  for (int i = 0; i < h.len - 1; i++) {vsh_crypt(dat[i], k2, &cd[i]);}
  free(d);
  pthread_exit(NULL);
  return 0;
}

//
// Server listener
int vsh_listen(int s, sock *cli) {
  int c = 1, *ns, len = sizeof(sock_in);

  listen(s, 3);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    ns = (int*)malloc(sizeof(*ns));
    *ns = c;
    if (pthread_create(&thrd, NULL, vsh_handler, (void*)ns) < 0) {return -1;}
    pthread_join(thrd, NULL);
    free(ns);
  }
  return c;
}

//
// Random uint64_t
u64 vsh_rand() {
  u64 r = 0;

  for (int i = 0; i < 5; ++i) { r = (r << 15) | (rand() & 0x7FFF);}
  return r & 0xFFFFFFFFFFFFFFFFULL;
}

//
// Generate a public and private keypair
key vsh_genkeys(u64 g, u64 p) {
  key k;

  k.priv = vsh_rand();
  k.publ = (u64)pow(g, k.priv) % p;
  return k;
}

//
// Generate the shared key
void vsh_genshare(key *k1, key *k2, u64 p, bool srv) {
  if (!srv) {(*k1).shar = p % (u64)pow((*k1).publ, (*k2).priv);}
  else {(*k2).shar = p % (u64)pow((*k2).publ, (*k1).priv);}
}

//
// Generate a keypair & shared key then print it (test / demo)
int vsh_keys() {
  u64 g1 = vsh_rand(), g2 = vsh_rand(), p1 = vsh_rand(), p2 = vsh_rand();
  u64 c = 123456, d = 0, e = 0;
  key k1 = vsh_genkeys(g1, p1), k2 = vsh_genkeys(g1, p2);

  vsh_genshare(&k1, &k2, p1, false);
  vsh_genshare(&k1, &k2, p1, true);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);

  vsh_crypt(c, k1, &d);
  vsh_crypt(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  assert(c == e);
  return c == e;
}

//
// Encrypt and decrypt data with shared key
void vsh_crypt(u64 data, key k, u64 *enc) {(*enc) = data ^ k.shar;}

//
// Get BLOCK size
int vsh_getblock() {return BLOCK;}

//
// Transfer keys (send and receive)
void vsh_transferkey(int s, bool snd, head *h, key *k) {
  key tmp;

  if (snd) {vsh_sendkey(s, h, k);}
  else {vsh_recvkey(s, h, &tmp);
    (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;}
    // This to ensure if we receive a private key we clear it
}

//
// Receive key
void vsh_recvkey(int s, head *h, key *k) {
  recv(s, h, sizeof(head), 0); recv(s, k, sizeof(key), 0); (*k).priv = 0;
  // This to ensure if we receive a private key we clear it
}

//
// Send key
void vsh_sendkey(int s, head *h, key *k) {
  key kk;

  // This to ensure not to send the private key
  kk.publ = (*k).publ; kk.shar = (*k).shar; kk.priv = 0;
  send(s, h, sizeof(head), 0); send(s, &kk, sizeof(key), 0);
}

//
// Transfer data (send and receive)
void vsh_transferdata(int s, void* data, bool snd, u64 len) {
  head h;

  if (snd) {send(s, &h, sizeof(head), 0); send(s, data, sizeof(u64) * len, 0);}
  else {recv(s, &h, sizeof(head), 0); recv(s, &data, sizeof(u64) * len, 0);}
}