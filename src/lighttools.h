GHTTOOLS_H
#define LIGHTTOOLS_H 1
#include <inttypes.h>
#include "lightdefs.h"

static char enc[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static u64 n1[] = {0x000003F, 0x0000FC0, 0x003F000, 0x01C0000, 0x0000800, 0x0000C080, 0x0010000, 0x00E08080, 0xF0808080},
  n2[] = {0x00EFBFBF, 0x000F0000, 0x003F0000, 0x07000000, 0x00003F00, 0x0000003F};

uint32_t utf8enc(uint32_t c);
uint32_t utf8dec(uint32_t c);
int err(char *s);
int lrand(uint8_t h[KB], u64 k[KB]);
int base64enc(char ed[], const uint8_t *data, int inl);
int base64dec(uint8_t dd[], const char *data, int inl);
void bit_pack(u64 big[6], const uint8_t byte[48]);
void bit_unpack(uint8_t byte[48], const u64 big[6]);
void bit_hex_str(char *hs, uint8_t *d, int len);
#endif
