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

uint32_t utf8enc(uint32_t c);
uint32_t utf8dec(uint32_t c);
int err(char *s);
int lrand(u64 h[KB], u64 k[KB]);
int base64enc(cuc *data, int inl, char ed[]);
int base64dec(cc *data, int inl, uint8_t dd[]);
void bit_pack(u64 big[6], const uint8_t byte[48]);
void bit_unpack(uint8_t byte[48], const u64 big[6]);
void bit_pack64(u64 n[6], const u64 b[48]);
void bit_unpack64(u64 b[48], const u64 n[6]);
#endif
