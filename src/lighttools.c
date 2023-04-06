#include <stdio.h>
#include <inttypes.h>
#include "lightdefs.h"
#include "lighttools.h"

static uint32_t oct(int i, int inl, const uint8_t d[257]) {
  if (i < inl) return d[i];
  return 0;
}

static uint32_t sex(const char d[257], char c[257], int i) {
  if (d[i] == '=') return (0 & i++);
  return c[(int)d[i]];
}

//
// Random rotate
static u64 prng_rotate(u64 x, u64 k) {
  return (x << k) | (x >> (32 - k));
}

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
  prng_ctx.a = 0xea7f00d1;

  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (u64 i = 0; i < 31; ++i) {(void)prng_next();}
}

//
// Error "handler"
int err(char *s) {
  printf("ERR: %s\n", s); return 1;
}


// https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c/66723102#66723102
// UTF8 encode/decode

// from UTF-8 encoding to Unicode Codepoint
uint32_t utf8dec(uint32_t c) {
  if (c > 0x7F) {
    uint32_t m = (c <= n2[0]) ? n2[1] : n2[2];
    c = ((c & n2[3]) >> 6) | ((c & m) >> 4) | ((c & n2[4]) >> 2) | (c & n2[5]);
  }
  return c;
}

// From Unicode Codepoint to UTF-8 encoding
uint32_t utf8enc(uint32_t c) {
  uint32_t m = c;

  if (c > 0x7F) {
    m = (c & n1[0]) | (c & n1[1]) << 2 | (c & n1[2]) << 4 | (c & n1[3]) << 6;
    if (c < n1[4]) m |= n1[5];
    else if (c < n1[6]) m |= n1[7];
    else m |= n1[8];
  }
  return m;
}

//
// Base64 encoder
int base64enc(const uint8_t *data, int inl, char ed[]) {
  int tab[] = {0, 2, 1}, ol = 4 * ((inl + 2) / 3);

  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = oct(i++, inl, data), b = oct(i++, inl, data);
    uint32_t c = oct(i++, inl, data), tri = (a << 0x10) + (b << 0x08) + c;
    for (int k = 3; k >=0; k--)
      ed[j++] = enc[(tri >> k * 6) & 0x3F];
  }
  for (int i = 0; i < tab[inl % 3]; i++)
    ed[ol - 1 - i] = '=';
  ed[ol] = '\0';
  return ol;
}

//
// Base64 decoder
int base64dec(const char *data, int inl, uint8_t dd[]) {
  static char dec[LEN] = {0};
  int ol = inl / 4 * 3;

  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') (ol)--;}
  for (int i = 0; i < 64; i++) dec[(uint8_t)enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = sex(data, dec, i++), b = sex(data, dec, i++);
    uint32_t c = sex(data, dec, i++), d = sex(data, dec, i++);
    uint32_t tri = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
    if (j < ol)
      for (int k = 2; k >= 0; k--)
        dd[j++] = (tri >> k * 8) & 0xFF;
  }
  return ol;
}

//
// "Randomizer"
int lrand(u64 h[KB], u64 k[KB]) {
  prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
  for (int i = 0; i < KB; ++i) {
    h[i] = prng_next(); k[i] = prng_next();
  }
  return 1;
}

// big[i] =
// ((uint64_t)dig[0] << 56) |
// ((uint64_t)dig[1] << 48) |
// ((uint64_t)dig[2] << 40) |
// ((uint64_t)dig[3] << 32) |
// ((uint64_t)dig[4] << 24) |
// ((uint64_t)dig[5] << 16) |
// ((uint64_t)dig[6] << 8) |
// (uint64_t)dig[7];
//
// Bit packing function uint8 to uint64
void bit_pack(u64 big[6], const uint8_t byte[48]) {
  for(uint32_t i = 0; i < 6; ++i) {
    const uint8_t *dig = byte + 8 * (6 - 1 - i);
    for (int j = 7; j >= 0; j--)
      big[i] |= ((u64)dig[7 - j] << (j * 8));
  }
}

// dig[0] = big[i] >> 56;
// dig[1] = big[i] >> 48;
// dig[2] = big[i] >> 40;
// dig[3] = big[i] >> 32;
// dig[4] = big[i] >> 24;
// dig[5] = big[i] >> 16;
// dig[6] = big[i] >> 8;
// dig[7] = big[i];
//
// Bit unpack uint64 to uint8
void bit_unpack(uint8_t byte[48], const u64 big[6]) {
  for(uint32_t i = 0; i < 6; ++i) {
    uint8_t *dig = byte + 8 * (6 - 1 - i);
    for (int j = 7; j >= 0; j--)
      dig[7 - j] = big[i] >> (j * 8);
  }
}

void bit_pack64(u64 n[DI], const u64 b[KB]) {
  for(u64 i = 0; i < DI; ++i) {
    const u64 *d = b + 8 * (DI - 1 - i); n[i] = 0;
    for (u64 j = 0; j < 8; j++)
      n[i] |= ((u64)d[j] << ((7 - j) * 8));
  }
}

void bit_unpack64(u64 b[KB], const u64 n[DI]) {
  for(u64 i = 0; i < DI; ++i) {
    u64 *d = b + 8 * (DI - 1 - i);
    for (u64 j = 0; j < 8; j++)
      d[j] = n[i] >> ((7 - j) * 8);
  }
}
