// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "keys.h"

// Static variables
static char enc[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static u64 curve_p[DIGITS] = {0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
  0xffffffffffffffff,0xffffffffffffffff}, curve_b[DIGITS] = {0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4}, curve_n[DIGITS] = {0xecec196accc52973, 0x581a0db248b0a77a,
  0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static pt curve_g = {{0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74,
  0xaa87ca22be8b0537},{0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d,0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c, 0x5d9e98bf9292dc29,
  0x3617de4a96262c6f}};

static uint32_t oct(int i, int inl, const uint8_t d[]) {
  if (i < inl) return d[i];
  return 0;
}

static uint32_t sex(const char d[], char c[], int i) {
  if (d[i] == '=') return (0 & i++);
  return c[(int)d[i]];
}

//
// Base64 encoder
int base64enc(char ed[], const uint8_t *data, int inl) {
  int tab[] = {0, 2, 1}, ol = 4 * ((inl + 2) / 3);
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = oct(i++, inl, data), b = oct(i++, inl, data), c = oct(i++, inl, data),tri = (a << 0x10)+(b << 0x08) + c;
    for (int k = 3; k >=0; k--)
      ed[j++] = enc[(tri >> k * 6) & 0x3f];
  }
  for (int i = 0; i < tab[inl % 3]; i++)
    ed[ol - 1 - i] = '=';
  ed[ol] = '\0';
  return ol;
}

//
// Base64 decoder
int base64dec(uint8_t dd[], const char *data, int inl) {
  static char dec[LEN] = {0};
  int ol = inl / 4 * 3;
  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') ol--;}
  for (int i = 0; i < 64; i++) dec[(uint8_t)enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = sex(data, dec, i++), b = sex(data, dec, i++), c = sex(data, dec, i++), d = sex(data, dec, i++);
    uint32_t tri = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
    if (j < ol)
      for (int k = 2; k >= 0; k--)
        dd[j++] = (tri >> k * 8) & 0xff;
  }
  return ol;
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
void bit_pack(u64 big[], const uint8_t byte[]) {
  for(uint32_t i = 0; i < 6; ++i) {
    const uint8_t *dig = byte + 8 * (6 - 1 - i); big[i] = 0;
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
void bit_unpack(uint8_t byte[], const u64 big[]) {
  for(uint32_t i = 0; i < 6; ++i) {
    uint8_t *dig = byte + 8 * (6 - 1 - i);
    for (int j = 7; j >= 0; j--)
      dig[7 - j] = big[i] >> (j * 8);
  }
}

//
// Securely randomize arrays
static void u64rnd_array(uint8_t h[], u64 k[], int len) {
  u64 f7 = 0x7fffffffffffffff;
  int r[2*len], f = open("/dev/urandom", O_RDONLY);
  int rr = read(f, &r, sizeof r);
  close(f);
  if (rr >= 0)
    for (int i = 0; i < len; ++i) {
      h[i] = (uint8_t)(r[i] & f7);
      k[i] = (u64)(r[i] & f7);
    }
}

//
// Clear a
static void clear(u64 *a) {
  memset(a, 0, DIGITS * sizeof(u64));
}

//
// Count 64bit in a
static u64 count(const u64 *a) {
  for (int i = DIGITS - 1; i >= 0; --i) {
    if (a[i] != 0) return (i + 1);
  }
  return 0;
}

//
// Set a from b
static void set(u64 *a, const u64 *b) {
  memcpy(a, b, DIGITS * sizeof(u64));
}

//
// Check if a is zero, return 1, if not return 0
static int check_zero(const u64 *a) {
  if (a[0] == 0 && memcmp(a, a + 1, (DIGITS - 1) * sizeof(a[0])) == 0) return 1;
  return 0;
}

//
// Check if bit a or b is set, if so return diff from zero
static u64 check_set(const u64 *a, const uint32_t b) {
  return (a[b / 64] & ((u64)1 << MOD(b, 64)));
}

//
// Check number of bits needed for a
static uint32_t check_bits(const u64 *a) {
  u64 i, nd = count(a), d = a[nd - 1];
  if (nd == 0) return 0;
  for (i = 0; d; ++i) d >>= 1;
  return ((nd - 1) * 64 + i);
}

//
// Compare a and b
static int compare(const u64 *a, const u64 *b) {
  for (int i = DIGITS - 1; i >= 0; --i) {
    if (a[i] > b[i]) return 1;
    else if (a[i] < b[i]) return -1;
  }
  return 0;
}

//
// Left shift
static u64 lshift(u64 *a, const u64 *b, const u64 c) {
  u64 ovr = 0;
  for (uint32_t i = 0; i < DIGITS; ++i) {
    u64 t = b[i];
    a[i] = (t << c) | ovr;
    ovr = t >> (64 - c);
  }
  return ovr;
}

//
// Right shift by 1
static void rshift1(u64 *a) {
  u64 *e = a, ovr = 0; a += DIGITS;
  while (a-- > e) {
    u64 t = *a;
    *a = (t >> 1) | ovr;
    ovr = t << 63;
  }
}

//
// Adds b and c
static u64 add(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0;
  for (uint32_t i = 0; i < DIGITS; ++i) {
    u64 s = b[i] + c[i] + ovr;
    if (s != b[i]) ovr = (s < b[i]);
    a[i] = s;
  }
  return ovr;
}

//
// Sub b and c
static u64 sub(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0;
  for (uint32_t i = 0; i < DIGITS; ++i) {
    u64 d = b[i] - c[i] - ovr;
    if (d != b[i]) ovr = (d > b[i]);
    a[i] = d;
  }
  return ovr;
}

//
// Multiply
static void mul(u64 *a, const u64 *b, const u64 *c) {
  u64 r2 = 0, di22 = DIGITS * 2 - 1;
  uint128 r = 0;
  for (uint32_t k = 0; k < di22; ++k) {
    u64 min = (k < DIGITS ? 0 : (k + 1) - DIGITS);
    for (u64 j = min; j <= k && j < DIGITS; ++j) {
      uint128 p = (uint128)b[j] * c[k - j]; // product
      r += p;
      r2 += (r < p);
    }
    a[k] = (u64)(r);
    r = (r >> 64) | (((uint128)r2) << 64);
    r2 = 0;
  }
  a[di22] = (u64)r;
}

//
//
static void omega_mul(u64 *a, const u64 *b) {
  set(a, b);
  u64 t[DIGITS], ovr = lshift(t, b, 32);
  a[DIGITS + 1] = ovr + add(a + 1, a + 1, t);
  a[DIGITS + 2] = add(a + 2, a + 2, b);
  ovr += sub(a, a, t);
  u64 d = a[DIGITS] - ovr;
  if (d > a[DIGITS]) {
    for (u64 i = 1 + DIGITS; ; ++i) {
     // --a[i];
      if (--a[i] != (u64)-1) break;
    }
  }
  a[DIGITS] = d;
}

//
// Modulo add
// https://www.jjj.de/fxt/fxtbook.pdf 39.1.1 add & sub
static void mod_add(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  u64 zeros[6] = {0};
  if (memcmp(c, zeros, (size_t)(6 * sizeof(u64))) == 0) set(a, b);
  else {
    u64 rb[DIGITS];
    sub(rb, m, c);
    if (compare(b, rb) >= 1) {
      sub(a, b, rb);
    } else {
      u64 rr[DIGITS];
      sub(rr, m, rb);
      add(a, rr, b);
    }
  }
}

//
// Modulo sub
static void mod_sub(u64 *a, const u64 *b, const u64 *c) {
  if (compare(b, c) >= 1) {
    sub(a, b, c);
  } else {
    u64 r[DIGITS];
    sub(r, curve_p, c);
    add(a, r, b);
  }
}

//
// Modulo mod
static void mod_mod(u64 *a, u64 *b) {
  u64 t[DIGITS*2];
  while (!check_zero(b + DIGITS)) {
    u64 ovr = 0;
    clear(t);
    clear(t + DIGITS);
    omega_mul(t, b + DIGITS);
    clear(b + DIGITS);
    for (u64 i = 0; i < DIGITS + 3; ++i) {
      u64 s = b[i] + t[i] + ovr;
      if (s != b[i]) ovr = (s < b[i]);
      b[i] = s;
    }
  }
  while (compare(b, curve_p) > 0) {sub(b, b, curve_p);}
  set(a, b);
}

//
// Modulo multiply
static void mod_mul(u64 *a, const u64 *b, const u64 *c) {
  u64 p[DIGITS * 2];
  mul(p, b, c);
  mod_mod(a, p);
}

//
// Modulo square
static void mod_sqr(u64 *a, const u64 *b) {
  u64 p[DIGITS* 2];
  mul(p, b, b);
  mod_mod(a, p);
}

//
// Modulo square root
static void mod_sqrt(u64 a[DIGITS]) {
  u64 p1[DIGITS] = {1}, r[DIGITS] = {1};
  add(p1, curve_p, p1);
  for (u64 i = check_bits(p1) - 1; i > 1; --i) {
    mod_sqr(r, r);
    if (check_set(p1, i)) mod_mul(r, r, a);
  }
  set(a, r);
}

//
// Modulo multiply (b * c) % m
static void mod_mod_mul(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  u64 ds, bs, pb, mb = check_bits(m), p[DIGITS * 2], mm[DIGITS * 2];
  mul(p, b, c);
  pb = check_bits(p + DIGITS);
  if (pb) pb += DIGITS * 64;
  else pb = check_bits(p);
  if (pb < mb) {
    set(a, p);
    return;
  }
  clear(mm);
  clear(mm + DIGITS);
  ds = (pb - mb) / 64;
  bs = MOD(pb - mb, 64);
  if (bs) mm[ds + DIGITS] = lshift(mm + ds, m, bs);
  else set(mm + ds, m);
  clear(a);
  a[0] = 1;
  while (pb > DIGITS * 64 || compare(mm, m) >= 0) {
    int cmp = compare(DIGITS + mm, DIGITS + p);
    if (cmp < 0 || (cmp == 0 && compare(mm, p) <= 0)) {
      if (sub(p, p, mm)) sub(DIGITS + p, DIGITS + p, a);
      sub(DIGITS + p, DIGITS + p, DIGITS + mm);
    }
    u64 ovr = (mm[DIGITS] & 0x01) << 63;
    rshift1(DIGITS + mm);
    rshift1(mm);
    mm[DIGITS - 1] |= ovr;
    --pb;
  }
  set(a, p);
}

static void rs_sub_au(u64 *a, const u64 *b, u64 *u, const u64 *v, const u64 *m, u64 car, const bool sb) {
  if (sb) {
    sub(a, a, b);
    rshift1(a);
    if (compare(u, v) < 0) add(u, u, m);
    sub(u, u, v);
  } else rshift1(a);
  if (!EVEN(u)) car = add(u, u, m);
  rshift1(u);
  if (car) u[DIGITS - 1] |= 0x8000000000000000;
}

//
// Modulo inversion
static void mod_invers(u64 *r, const u64 *p, const u64 *m) {
  u64 a[DIGITS], b[DIGITS], u[DIGITS], v[DIGITS], tmp[DIGITS] = {0}, car;
  int cmpResult;
  if(check_zero(p)) {
    clear(r);
    return;
  }
  set(a, p);
  set(b, m);
  clear(u);
  u[0] = 1;
  clear(v);
  while ((cmpResult = compare(a, b)) != 0) {
    car = 0;
    if (EVEN(a)) rs_sub_au(a, tmp, u, tmp, m, car, false);
    else if (EVEN(b)) rs_sub_au(b, tmp, v, tmp, m, car, false);
    else if (cmpResult > 0) rs_sub_au(a, b, u, v, m, car, true);
    else rs_sub_au(b, a, v, u, m, car, true);
  }
  set(r, u);
}

//
// Points is this zero?
static int pt_check_zero(const pt *a) {
  return (check_zero(a->x) && check_zero(a->y));
}

//
// Points double
static void pt_double(u64 *a, u64 *b, u64 *c) {
  u64 t4[DIGITS], t5[DIGITS];
  if (check_zero(c)) return;
  mod_sqr(t4, b);
  mod_mul(t5, a, t4);
  mod_sqr(t4, t4);
  mod_mul(b, b, c);
  mod_sqr(c, c);

  mod_add(a, a, c, curve_p);
  mod_add(c, c, c, curve_p);
  mod_sub(c, a, c);
  mod_mul(a, a, c);

  mod_add(c, a, a, curve_p);
  mod_add(a, a, c, curve_p);
  if (check_set(a, 0)) {
    u64 ovr = add(a, a, curve_p);
    rshift1(a);
    a[DIGITS - 1] |= ovr << 63;
  } else rshift1(a);
  mod_sqr(c, a);
  mod_sub(c, c, t5);
  mod_sub(c, c, t5);
  mod_sub(t5, t5, c);
  mod_mul(a, a, t5);
  mod_sub(t4, a, t4);
  set(a, c);
  set(c, b);
  set(b, t4);
}

//
// Points decompress
static void pt_decompress(pt *a, const uint8_t b[]) {
  u64 tr[DIGITS] = {3};
  bit_pack(a->x, b + 1);
  mod_sqr(a->y, a->x);
  mod_sub(a->y, a->y, tr);
  mod_mul(a->y, a->y, a->x);
  mod_add(a->y, a->y, curve_b, curve_p);
  mod_sqrt(a->y);
  if ((a->y[0] & 0x01) != (b[0] & 0x01)) sub(a->y, curve_p, a->y);
}

//
// Points apply z
// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
static void pt_apply_z(u64 *a, u64 *b, const u64 *z) {
  u64 t[DIGITS];
  mod_sqr(t, z);
  mod_mul(a, a, t);
  mod_mul(t, t, z);
  mod_mul(b, b, t);
}

//
// Points init double
// P = (x1, y1) => 2P, (x2, y2) => P'
static void pt_init_double(u64 *a, u64 *b, u64 *c, u64 *d, const u64 *p) {
  u64 z[DIGITS];
  set(c, a);
  set(d, b);
  clear(z);
  z[0] = 1;
  if (p) set(z, p);
  pt_apply_z(a, b, z);
  pt_double(a, b, z);
  pt_apply_z(c, d, z);
}

static void ssmm(u64 *t5, u64 *c, u64 *a) {
  mod_sub(t5, c, a);
  mod_sqr(t5, t5);
  mod_mul(a, a, t5);
  mod_mul(c, c, t5);
}

//
// Points add
static void pt_add(u64 *a, u64 *b, u64 *c, u64 *d) {
  u64 t5[DIGITS];
  ssmm(t5, c, a);
  mod_sub(d, d, b);
  mod_sqr(t5, d);

  mod_sub(t5, t5, a);
  mod_sub(t5, t5, c);
  mod_sub(c, c, a);

  mod_mul(b, b, c);
  mod_sub(c, a, t5);
  mod_mul(d, d, c);
  mod_sub(d, d, b);
  set(c, t5);
}

//
// Points add
// t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
static void pt_addc(u64 *a, u64 *b, u64 *c, u64 *d) {
  u64 t5[DIGITS], t6[DIGITS], t7[DIGITS];
  ssmm(t5, c, a);
  mod_add(t5, d, b, curve_p);
  mod_sub(d, d, b);
  mod_sub(t6, c, a);
  mod_mul(b, b, t6);
  mod_add(t6, a, c, curve_p);
  mod_sqr(c, d);
  mod_sub(c, c, t6);

  mod_sub(t7, a, c);
  mod_mul(d, d, t7);
  mod_sub(d, d, b);

  mod_sqr(t7, t5);
  mod_sub(t7, t7, t6);
  mod_sub(t6, t7, a);
  mod_mul(t6, t6, t5);
  mod_sub(b, t6, b);
  set(a, t7);
}

//
// Point multiplication
static void pt_mul(pt *r, pt *p, const u64 *q, const u64 *s) {
  u64 Rx[2][DIGITS], Ry[2][DIGITS], z[DIGITS], nb;
  set(Rx[1], p->x);
  set(Ry[1], p->y);
  pt_init_double(Rx[1], Ry[1], Rx[0], Ry[0], s);
  for (int i = check_bits(q) - 2; i > 0; --i) {
    nb = !check_set(q, i);
    pt_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
    pt_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
  }
  nb = !check_set(q, 0);
  pt_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
  // Find final 1/Z value.
  mod_sub(z, Rx[1], Rx[0]);
  mod_mul(z, z, Ry[1 - nb]);
  mod_mul(z, z, p->x);
  mod_invers(z, z, curve_p);
  mod_mul(z, z, p->y);
  mod_mul(z, z, Rx[1 - nb]);

  pt_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
  pt_apply_z(Rx[0], Ry[0], z);
  set(r->x, Rx[0]);
  set(r->y, Ry[0]);
}

//
// Write cert to file
static u64 write_crt(FILE* ptr, const uint8_t data[]) {
  int i = 4;
  fprintf(ptr, "-----BEGIN CERTIFICATE-----\n");
  fprintf(ptr, "MII");
  while (i < 1779) {
    fputc('y', ptr);
    if (i % 64 == 0) fputc('\n', ptr);
    i++;
  }
  fprintf(ptr, "==\n");
  fprintf(ptr, "-----END CERTIFICATE-----\n");
  return 1;
}

//
// Write key to file
// Public key: https://datatracker.ietf.org/doc/html/rfc5480
// Private key: https://datatracker.ietf.org/doc/html/rfc5915.html
static u64 write_key(FILE* ptr, const uint8_t data[]) {
  char tmp[257] = {0};
  uint8_t d[BYTES] = {0};
  int i = 10, j = 0;
  bit_unpack(d, (u64*)data);
  j = base64enc(tmp, d, 164);
  fprintf(ptr, "-----BEGIN EC PRIVATE KEY-----\n");
  while (i < j) {
    if (i % 64 == 0) fprintf(ptr, "\n");
    fprintf(ptr, "%c", tmp[(i++) - 10]);
  }
  fprintf(ptr, "=\n-----END EC PRIVATE KEY-----\n");
  return 1;
}

//
// Write cms to file
static u64 write_cms(FILE* ptr, const uint8_t data[]) {
  fprintf(ptr, "%s\n", data);
  return 1;
}

//
// Write certificates/keys/cms
u64 keys_write(char *fn, uint8_t data[], const int type) {
  FILE* ptr = fopen(fn, "w");
  u64 ret = 0;
  if (type == 1) ret = write_crt(ptr, data); // Certificate
  if (type == 2) ret = write_key(ptr, data); // Private key
  if (type == 3) ret = write_cms(ptr, data); // CMS
  fclose(ptr);
  return ret;
}

//
// Make public key
int keys_make(uint8_t publ[], uint8_t priv[]) {
  u64 p[DIGITS], k[BYTES] = {0};
  uint8_t h[BYTES] = {0};
  pt public;
  u64rnd_array(h, k, BYTES);
  set(p, k);
  while(true) {
    if (compare(curve_n, p) != 1) sub(p, p, curve_n);
    pt_mul(&public, &curve_g, p, NULL);
    if (!pt_check_zero(&public)) break;
  }
  bit_unpack(priv, p);
  bit_unpack(publ + 1, public.x);
  publ[0] = 2 + (public.y[0] & 0x01);
  return 1;
}

//
// Create a secret from the public and private key
int keys_secr(const uint8_t pub[], const uint8_t prv[], uint8_t scr[]) {
  u64 private[DIGITS], k[BYTES] = {0};
  uint8_t h[BYTES] = {0};
  pt public, product;
  u64rnd_array(h, k, BYTES);
  pt_decompress(&public, pub);
  bit_pack(private, prv);
  pt_mul(&product, &public, private, (u64*)h);
  bit_unpack(scr, product.x);
  return !pt_check_zero(&product);
}

//
// Create signature
int keys_sign(const uint8_t priv[], uint8_t hash[], uint8_t sign[]) {
  u64 tmp[DIGITS], s[DIGITS], kk[BYTES] = {0};
  uint8_t h[BYTES] = {0};
  int firstrun = 0;
  pt p;
  u64rnd_array(h, kk, BYTES);
  memcpy(hash, (uint8_t*)h, BYTES * sizeof(uint8_t));
  while (check_zero(p.x) || firstrun++ <= 1) {
    if (check_zero(kk)) continue;
    if (compare(curve_n, kk) != 1) sub(kk, kk, curve_n);
    pt_mul(&p, &curve_g, kk, NULL);
    if (compare(curve_n, p.x) != 1) sub(p.x, p.x, curve_n);
  }
  bit_unpack(sign, p.x);
  bit_pack(tmp, priv);
  mod_mod_mul(s, p.x, tmp, curve_n);
  bit_pack(tmp, hash);
  mod_add(s, tmp, s, curve_n);
  mod_invers(kk, kk, curve_n);
  mod_mod_mul(s, s, kk, curve_n);
  bit_unpack(sign + BYTES, s);
  return 1;
}

//
// Verify signature
int keys_vrfy(const uint8_t publ[], const uint8_t hash[], const uint8_t sign[]) {
  u64 u1[DIGITS] = {0}, u2[DIGITS] = {0}, tx[DIGITS] = {0}, ty[DIGITS] = {0}, tz[DIGITS] = {0};
  u64 rx[DIGITS] = {0}, ry[DIGITS] = {0}, rz[DIGITS] = {0};
  pt public, sum;
  pt_decompress(&public, publ);
  bit_pack(rx, sign);
  bit_pack(ry, sign + BYTES);
  if (check_zero(rx) || check_zero(ry)) return 0;
  if (compare(curve_n, rx) != 1 || compare(curve_n, ry) != 1) return 0;
  mod_invers(rz, ry, curve_n);
  bit_pack(u1, hash);
  mod_mod_mul(u1, u1, rz, curve_n);
  mod_mod_mul(u2, rx, rz, curve_n);
  // Calculate sum = G + Q.
  set(sum.x, public.x);
  set(sum.y, public.y);
  set(tx, curve_g.x);
  set(ty, curve_g.y);
  mod_sub(rz, sum.x, tx);
  pt_add(tx, ty, sum.x, sum.y);
  mod_invers(rz, rz, curve_p);
  pt_apply_z(sum.x, sum.y, rz);
  // Use Shamir's trick to calculate u1*G + u2*Q
  pt *points[4] = {NULL, &curve_g, &public, &sum};
  uint32_t nb = (check_bits(u1) > check_bits(u2) ? check_bits(u1) : check_bits(u2));
  uint32_t n1 = (!!check_set(u1, nb - 1)) | ((!!check_set(u2, nb - 1)) << 1);
  set(rx, points[n1]->x);
  set(ry, points[n1]->y);
  clear(rz);
  rz[0] = 1;
  for (int i = nb - 2; i >= 0; --i) {
    pt_double(rx, ry, rz);
    uint32_t n2 = (!!check_set(u1, i)) | ((!!check_set(u2, i)) << 1);
    if (n2) {
      set(tx, points[n2]->x);
      set(ty, points[n2]->y);
      pt_apply_z(tx, ty, rz);
      mod_sub(tz, rx, tx);
      pt_add(tx, ty, rx, ry);
      mod_mul(rz, rz, tz);
    }
  }
  mod_invers(rz, rz, curve_p);
  pt_apply_z(rx, ry, rz);
  if (compare(curve_n, rx) != 1) sub(rx, rx, curve_n);
  bit_pack(ry, sign);
  return (compare(rx, ry) == 0);
}


// ECDSA
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// https://www.rfc-editor.org/rfc/rfc6979
// https://www.rfc-editor.org/rfc/rfc4050

// http://www.secg.org/sec2-v2.pdf
// http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
// https://www.ietf.org/rfc/rfc4492.txt

// https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
// https://www.ietf.org/rfc/rfc4492.txt

// secp384r1
// Rewritten from https://github.com/jestan/easy-ecc
