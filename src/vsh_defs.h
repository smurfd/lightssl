#ifndef VSH_DEFS_H
#define VSH_DEFS_H 1

#define BLOCK 1024

struct header {
  uint64_t len;
  uint64_t ver;
  uint64_t othr;
  uint64_t stuff;
  uint64_t here;
} header;

#endif
