//                                                                            //
// Very simple handshake
#ifndef VSH_DEFS_H
#define VSH_DEFS_H 1

#define BLOCK 1024

typedef uint64_t u64;
typedef struct keys key;
typedef struct header head;
typedef struct sockaddr sock;
typedef struct sockaddr_in sock_in;

struct header {
  u64 len;
  u64 ver;
  u64 othr;
  u64 stuff;
  u64 here;
};

struct keys {
  u64 publ;
  u64 priv;
  u64 shar;
};

#endif
