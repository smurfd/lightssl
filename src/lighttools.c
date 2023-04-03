#include <inttypes.h>
#include "lightdefs.h"
#include "lighttools.h"

static uint32_t lcoct(int i, int inl, cuc d[257]) {
  if (i < inl) {return d[i];} else {return 0;}
}

static uint32_t lcsex(cc d[257], char c[257], int i) {
  if (d[i] == '=') {return 0 & i++;} else {return c[(int)d[i]];}
}
// https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c/66723102#66723102
// UTF8 encode/decode

// from UTF-8 encoding to Unicode Codepoint
uint32_t lcutf8decode(uint32_t c) {
  u64 n[] = {0x00EFBFBF, 0x000F0000, 0x003F0000, 0x07000000, 0x00003F00,
    0x0000003F};
  uint32_t mask;

  if (c > 0x7F) {
    mask = (c <= n[0]) ? n[1] : n[2];
    c = ((c & n[3]) >> 6) | ((c & mask ) >> 4) | ((c & n[4]) >> 2) | (c & n[5]);
  }
  return c;
}

// From Unicode Codepoint to UTF-8 encoding
uint32_t lcutf8encode(uint32_t cp) {
  u64 n[] = {0x000003F, 0x0000FC0, 0x003F000, 0x01C0000, 0x0000800,
    0x0000C080, 0x0010000, 0x00E08080, 0xF0808080};
  uint32_t c = cp;

  if (cp > 0x7F) {
    c = (cp & n[0]) | (cp & n[1]) << 2 | (cp & n[2]) << 4 | (cp & n[3]) << 6;
    if (cp < n[4]) c |= n[5]; else if (cp < n[6]) c |= n[7]; else c |= n[8];
  }
  return c;
}

int base64enc(cuc *data, int inl, char ed[]) {
  int tab[] = {0, 2, 1}, ol = 4 * ((inl + 2) / 3);

  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = lcoct(i++, inl, data), b = lcoct(i++, inl, data);
    uint32_t c = lcoct(i++, inl, data), tri = (a << 0x10) + (b << 0x08) + c;
    for (int k = 3; k >=0; k--) {ed[j++] = enc[(tri >> k * 6) & 0x3F];}
  }
  for (int i = 0; i < tab[inl % 3]; i++) ed[ol - 1 - i] = '='; ed[ol] = '\0';
  return ol;
}

int base64dec(cc *data, int inl, uint8_t dd[]) {
  static char dec[LEN] = {0};
  int ol = inl / 4 * 3;

  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') (ol)--;}
  for (int i = 0; i < 64; i++) dec[(uint8_t)enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = lcsex(data, dec, i++), b = lcsex(data, dec, i++);
    uint32_t c = lcsex(data, dec, i++), d = lcsex(data, dec, i++);
    uint32_t tri = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
    if (j < ol) {for (int k = 2; k >= 0; k--) dd[j++] = (tri >> k * 8) & 0xFF;}
  }
  return ol;
}

//
// Random rotate
static u64 prng_rotate(u64 x, u64 k) {return (x << k) | (x >> (32 - k));}

//
// Random next
static u64 prng_next(void) {
  u64 e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);

  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

//
// Random init
static void prng_init(u64 seed) {
  prng_ctx.a = 0xea7f00d1; prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (u64 i = 0; i < 31; ++i) {(void)prng_next();}
}

//
//
int lkrand(u64 h[KB], u64 k[KB]) {
  prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
  for (int i = 0; i < KB; ++i) {h[i] = prng_next(); k[i] = prng_next();}
  return 1;
}

void pack(uint64_t big[6], const uint8_t byte[48]) {
  for(uint32_t i = 0; i < 6; ++i) {
    const uint8_t *dig = byte + 8 * (6 - 1 - i);
        big[i] = ((uint64_t)dig[0] << 56) |
        ((uint64_t)dig[1] << 48) |
        ((uint64_t)dig[2] << 40) |
        ((uint64_t)dig[3] << 32) |
        ((uint64_t)dig[4] << 24) |
        ((uint64_t)dig[5] << 16) |
        ((uint64_t)dig[6] << 8) |
        (uint64_t)dig[7];
  }
}

void unpack(uint8_t byte[48], const uint64_t big[48/8]) {
  for(uint32_t i = 0; i < 6; ++i) {
    uint8_t *dig = byte + 8 * (6 - 1 - i);
    dig[0] = big[i] >> 56;
    dig[1] = big[i] >> 48;
    dig[2] = big[i] >> 40;
    dig[3] = big[i] >> 32;
    dig[4] = big[i] >> 24;
    dig[5] = big[i] >> 16;
    dig[6] = big[i] >> 8;
    dig[7] = big[i];
  }
}
