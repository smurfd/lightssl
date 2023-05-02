// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTTOOLS_H
#define LIGHTTOOLS_H 1
#include <inttypes.h>
#include "lightdefs.h"

static char enc[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static u64 n1[] = {0x000003f, 0x0000fc0, 0x003f000, 0x01c0000, 0x0000800, 0x0000c080, 0x0010000, 0x00e08080, 0xf0808080},
           n2[] = {0x00efbfbf, 0x000f0000, 0x003f0000, 0x07000000, 0x00003f00, 0x0000003f};

uint32_t utf8enc(uint32_t c);
uint32_t utf8dec(uint32_t c);
int err(char *s);
int lrand(uint8_t h[], u64 k[]);
int base64enc(char ed[], const uint8_t *data, int inl);
int base64dec(uint8_t dd[], const char *data, int inl);
void bit_pack(u64 big[], const uint8_t byte[]);
void bit_unpack(uint8_t byte[], const u64 big[]);
void bit_hex_str(char hs[], const uint8_t *d, const int len);
#endif
