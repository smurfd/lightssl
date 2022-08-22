#ifndef VSH_DEFS_H
#define VSH_DEFS_H 1

#define BLOCK 1024
typedef uint64_t u64;

struct header {
  u64 len;
  u64 ver;
  u64 othr;
  u64 stuff;
  u64 here;
} header;

#endif
