//                                                                            //
#ifndef LIGHTTOOLS_H
#define LIGHTTOOLS_H 1
#include <inttypes.h>
#include "lightdefs.h"

static char enc[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
  'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'};

uint32_t lcutf8decode(uint32_t c);
uint32_t lcutf8encode(uint32_t cp);
int lkrand(u64 h[KB], u64 k[KB]);
int base64enc(cuc *data, int inl, char ed[]);
int base64dec(cc *data, int inl, uint8_t dd[]);
void pack(uint64_t big[6], const uint8_t byte[48]);
void unpack(uint8_t byte[48], const uint64_t big[48/8]);
#endif
