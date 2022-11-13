// ECDSA
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// https://www.rfc-editor.org/rfc/rfc6979
// https://www.rfc-editor.org/rfc/rfc4050

// https://github.com/smurfd/lightecdh ?


// http://www.secg.org/sec2-v2.pdf
// http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
// https://www.ietf.org/rfc/rfc4492.txt

// https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
// https://www.ietf.org/rfc/rfc4492.txt

// secp384r1
// Rewritten from https://github.com/jestan/easy-ecc
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "lightdefs.h"
//#include "lightkeys_defs.h"

//
// Imitate pythons %. -1 % 5 = 4, not -1
static int mod(const int n, const int m) {return ((n % m) + m) % m;}

//
// Clear a
static void keys_clear(u64 *a) {for (uint8_t i = 0; i < DI; ++i) {a[i] = 0;}}//memset(a, 0, DI);}

//
// Check if a is zero, return 1, if not return 0
static int keys_zero(const u64 *a) {
  //static const u64 zr[DI] = {0}; return !memcmp(a, zr, DI);
  for (uint8_t i = 0; i < DI; ++i) {
    if (a[i]) {return 0;}
  }
  return 1;
}

//
// Check if bit a or b is set, if so return diff from zero
static u64 keys_chk(const u64 *a, const ui b) {
  return (a[b / 64] & ((u64)1 << (mod(b, 64))));
}

//
// Count 64bit in a
static ui keys_count(const u64 *a) {
  int i = DI - 1; while(i >= 0 && a[i] == 0) {--i;} return (i + 1);
}

//
// Set a from b
static void keys_set(u64 *a, const u64 *b) {
  for (uint8_t i = 0; i < DI; ++i) {a[i] = b[i];}

  //memcpy(a, b, DI);
}

//
// Check number of bits needed for a
static ui keys_bits(u64 *a) {
  ui i, nd = keys_count(a); u64 d;
  if (nd == 0) return 0;
  nd--; d = a[nd];
  for (i = 0; d; ++i) d >>= 1;
  return (nd * 64 + i);
}

//
// Compare a and b
static int keys_cmp(const u64 *a, const u64 *b) {
  for (int i = DI-1; i >= 0; --i) {
    if (a[i] > b[i]) {
      return 1;
    } else if (a[i] < b[i]) {
      return -1;
    }
  }
  return 0;
//  int c = memcmp(a, b, DI);
//  if (c < 0) return -1;
//  if (c > 0) return 1;
//  return 0;
}

//
// Left shift
static u64 keys_ls(u64 *a, const u64 *b, const ui c) {
  u64 ovr = 0;
  for (uint8_t i = 0; i < DI; ++i) {
    u64 t = b[i]; a[i] = (t << c) | ovr;
    ovr = t >> (64 - c);
  }
  return ovr;
}

//
// Right shift by 1
static void keys_rs1(u64 *a) {
  u64 *e = a, ovr = 0;
  a += DI;
  while (a-- > e) {
    u64 t = *a; *a = (t >> 1) | ovr;
    ovr = t << 63;
  }
}

//
// Adds b and c
static u64 keys_add(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0;
  for (uint8_t i = 0; i < DI; ++i) {
    u64 s = b[i] + c[i] + ovr;
    if (s != b[i]) {ovr = (s < b[i]);} a[i] = s;
  }
  return ovr;
}

//
// Sub b and c
static u64 keys_sub(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0;
  for (uint8_t i = 0; i < DI; ++i) {
    u64 d = b[i] - c[i] - ovr;
    if (d != b[i]) {ovr = (d > b[i]);} a[i] = d;
  }
  return ovr;
}

static void akr(u64 *a, u64 k, u128 r, u64 r2) {
  a[k] = (u64)r; r = (r >> 64) | ((u128)r2 << 64); r2 = 0;
}

//
//
static void keys_mul(u64 *a, const u64 *b, const u64 *c) {
  u128 r = 0; u64 r2 = 0, di22 = DI * 2 - 1;
  for (uint8_t k = 0; k < di22; ++k) {
    ui min = (k < DI ? 0 : (k + 1) - DI);
    for (uint8_t j = min; j <= k && j < DI; ++j) {
      u128 p = (u128)b[j] * c[k - j]; // product
      r += p; r2 += (r < p);
    }
    //akr(a, k, r, r2);
    a[k] = (u64)r;
    r = (r >> 64) | ((u128)r2 << 64);
    r2 = 0;
  }
  a[di22] = (u64)r;
}

static void keys_sqr(u64 *a, const u64 *b) {
  u128 r = 0; u64 r2 = 0, di22 = DI * 2 - 1;
  for (uint8_t k = 0; k < di22; ++k) {
    ui min = (k < DI ? 0 : (k + 1) - DI);
    for (uint8_t j = min; j <= k && j <= k - j; ++j) {
      u128 p = (u128)b[j] * b[k - j]; // product
      if (j < k - j) {r2 += p >> 127; p *= 2;}
      r += p; r2 += (r < p);
    }
    //akr(a, k, r, r2);
    a[k] = (u64)r;
    r = (r >> 64) | (((u128)r2) << 64);
    r2 = 0;
  }
  a[di22] = (u64)r;
}

//
static void keys_o_mul(u64 *a, const u64 *b) {
  u64 t[DI], ovr;

  keys_set(a, b);
  ovr = keys_ls(t, b, 32);
  a[1+DI] = ovr + keys_add(a + 1, a + 1, t);
  a[2+DI] = keys_add(a + 2, a + 2, b);
  ovr += keys_sub(a, a, t);
  u64 d = a[DI] - ovr;
  printf("here\n");
  if (d > a[DI]) {
    for (uint8_t i = 1+DI; ; ++i) {
      --a[i];
      if (a[i] != (u64) - 1) {break;}
    }
  }
  a[DI] = d;
}

// Modulo functions
static void keys_m_add(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (keys_add(a, b, c) || keys_cmp(a, m) >= 0) {keys_sub(a, a, m);}
}

static void keys_m_sub(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (keys_sub(a, b, c)) {keys_add(a, a, m);}
}

static void keys_m_mod(u64 *a, u64 *b) {
  u64 t[DI2];
  while (!keys_zero(b + DI)) {
    u64 ovr = 0;
    keys_clear(t); keys_clear(t + DI);
    keys_o_mul(t, b + DI);
    keys_clear(b + DI);
    for (uint8_t i = 0; i < DI + 3; ++i) {
      u64 s = b[i] + t[i] + ovr;
      if (s != b[i]) {ovr = (s < b[i]);}
      b[i] = s;
    }
  }
  printf("-----------------\n");
  while (keys_cmp(b, curve_p) > 0) {keys_sub(b, b, curve_p);printf("*\n");}
  printf("///\n");
  keys_set(a, b);
  printf("///\n");

}

static void keys_m_mul(u64 *a, const u64 *b, const u64 *c) {
  u64 p[DI2];
  keys_mul(p, b, c);
  printf("m_mul\n");
  keys_m_mod(a, p);
    printf("m_mul\n");

}

static void keys_m_sqr(u64 *a, const u64 *b) {
  u64 p[DI2];
  printf("--\n");
  keys_sqr(p, b);
  printf("--\n");
  keys_m_mod(a, p);
  printf("--\n");
}

static void keys_m_sqrt(u64 a[DI]) {
  u64 p1[DI] = {1}, r[DI] = {1};
  keys_add(p1, curve_p, p1);
  for (ui i = keys_bits(p1) - 1; i > 1; --i) {
    keys_m_sqr(r, r);
    if (keys_chk(p1, i)) {keys_m_mul(r, r, a);}
  }
  printf("m_sqrt\n");
  keys_set(a, r);
}

static void keys_m_mmul(u64 *a, u64 *b, u64 *c, u64 *m) {
  u64 p[DI2], mm[DI2];
  ui ds, bs, pb, mb = keys_bits(m);
  keys_mul(p, b, c);
  pb = keys_bits(p + DI);
  if (pb) {pb += DI * 64;}
  else {pb = keys_bits(p);};
  if (pb < mb) {keys_set(a, p); return;}

  keys_clear(mm); keys_clear(mm + DI);
  ds = (pb - mb) / 64; bs = mod(pb - mb, 64);
  if (bs) {mm[ds + DI] = keys_ls(mm + ds, m, bs);}
  else {keys_set(mm + ds, m);}

  keys_clear(a); a[0] = 1;
  while (pb > DI * 64 || keys_cmp(mm, m) >= 0) {
    int cmp = keys_cmp(DI + mm, DI + p);
    if (cmp < 0 || (cmp == 0 && keys_cmp(mm, p) <= 0)) {
      if (keys_sub(p, p, mm)) {keys_sub(DI + p, DI + p, a);}
      keys_sub(DI + p, DI + p, DI + mm);
    }
    u64 ovr = (mm[DI] & 0x01) << 63;
    keys_rs1(DI + mm); keys_rs1(mm);
    mm[DI - 1] |= ovr;
    --pb;
  }
  keys_set(a, p);
}

// Points functions
static int keys_p_zero(pt *a) {return (keys_zero(a->x) && keys_zero(a->y));}

static void keys_p_double(u64 *a, u64 *b, u64 *c) {
  u64 t4[DI], t5[DI];
  if (keys_zero(c)) {return;}
  printf("p_duble\n");
  keys_m_sqr(t4, b);
  keys_m_mul(t5, a, t4);
  keys_m_sqr(t4, t4);
  keys_m_mul(b, b, c);
  keys_m_sqr(c, c);

  keys_m_add(a, a, c, curve_p);
  keys_m_add(c, c, c, curve_p);
  keys_m_sub(c, a, c, curve_p);
  keys_m_mul(a, a, c);

  keys_m_add(c, a, a, curve_p);
  keys_m_add(a, a, c, curve_p);
  if (keys_chk(a, 0)) {
    u64 ovr = keys_add(a, a, curve_p);
    keys_rs1(a);
    a[DI - 1] |= ovr << 63;
  } else {keys_rs1(a);}
  keys_m_sqr(c, a);
  keys_m_sub(c, c, t5, curve_p);
  keys_m_sub(c, c, t5, curve_p);
  keys_m_sub(t5, t5, c, curve_p);
  keys_m_mul(a, a, t5);
  keys_m_sub(t4, a, t4, curve_p);
  keys_set(a, c);
  keys_set(c, b);
  keys_set(b, t4);
}

static void keys_p_decom(pt *a, const u64 b[DI + 1]) {
  u64 tr[DI] = {3};
  printf(".....\n");
  keys_set(a->x, b + 1);
  printf(".....\n");
  keys_m_sqr(a->y, a->x);
  printf(".....\n");
  keys_m_sub(a->y, a->y, tr, curve_p);
  printf(".....\n");
  keys_m_mul(a->y, a->y, a->x);
  printf(".....\n");
  keys_m_add(a->y, a->y, curve_b, curve_p);
  printf(".....\n");
  keys_m_sqrt(a->y);
  printf(".....\n");
  if ((a->y[0] & 0x01) != (b[0] & 0x01)) {keys_sub(a->y, curve_p, a->y);}
}

static void keys_p_appz(u64 *a, u64 *b, const u64 *z) {
  u64 t[DI];
  keys_m_sqr(t, z);
  printf("appz\n");
  keys_m_mul(a, a, t);
  keys_m_mul(t, t, z);
  keys_m_mul(b, b, t);
}

// P = (x1, y1) => 2P, (x2, y2) => P'
static void keys_p_inidoub(u64 *a, u64 *b, u64 *c, u64 *d, u64 *p) {
  u64 z[DI];
  keys_set(c, a); keys_set(d, b);
  keys_clear(z); z[0] = 1;
  if (p) {keys_set(z, p);}
  keys_p_appz(a, c, z);
  keys_p_double(a, c, z);
  keys_p_appz(b, d, z);
}

static void keys_p_add(u64 *a, u64 *b, u64 *c, u64 *d) {
  u64 t5[DI];
  keys_m_sub(t5, c, a, curve_p);
  keys_m_sqr(t5, t5);
  printf("p_add\n");
  keys_m_mul(a, a, t5);
  keys_m_mul(c, c, t5);
  keys_m_sub(d, d, b, curve_p);
  keys_m_sqr(t5, d);

  keys_m_sub(t5, t5, a, curve_p);
  keys_m_sub(t5, t5, c, curve_p);
  keys_m_sub(c, c, a, curve_p);
  keys_m_mul(b, b, c);
  keys_m_sub(c, a, t5, curve_p);
  keys_m_mul(d, d, c);
  keys_m_sub(d, d, b, curve_p);
  keys_set(c, t5);
}

static void keys_p_addc(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  u64 t5[DI], t6[DI], t7[DI];

  keys_m_sub(t5, X2, X1, curve_p);
  keys_m_sqr(t5, t5);
  printf("p_addc\n");
  keys_m_mul(X1, X1, t5);
  keys_m_mul(X2, X2, t5);
  keys_m_add(t5, Y2, Y1, curve_p);
  keys_m_sub(Y2, Y2, Y1, curve_p);

  keys_m_sub(t6, X2, X1, curve_p);
  keys_m_mul(Y1, Y1, t6);
  keys_m_add(t6, X1, X2, curve_p);
  keys_m_sqr(X2, Y2);
  keys_m_sub(X2, X2, t6, curve_p);
  printf("p_addc\n");

  keys_m_sub(t7, X1, X2, curve_p);
  keys_m_mul(Y2, Y2, t7);
  keys_m_sub(Y2, Y2, Y1, curve_p);
  printf("p_addc\n");

  keys_m_sqr(t7, t5);
  keys_m_sub(t7, t7, t6, curve_p);
  keys_m_sub(t6, t7, X1, curve_p);
  keys_m_mul(t6, t6, t5);
  keys_m_sub(Y1, t6, Y1, curve_p);
  keys_set(X1, t7);
  printf("p_addc---------\n");
}

static void keys_m_inv(u64 *r, u64 *p, u64 *m) {
  u64 a[DI], b[DI], u[DI], v[DI], car;
  int cmpResult;
  if(keys_zero(p)) {keys_clear(r); return;}
  keys_set(a, p);
  keys_set(b, m);
  keys_clear(u); u[0] = 1;
  keys_clear(v);
  while ((cmpResult = keys_cmp(a, b)) != 0) {
    car = 0;
    printf("loop\n");
    if (EVEN(a)) {
      keys_rs1(a);
      if (!EVEN(u)) {car = keys_add(u, u, m);}
      keys_rs1(u);
      if (car) {u[DI - 1] |= 0x8000000000000000;}
    } else if (EVEN(b)) {
      keys_rs1(b);
      if (!EVEN(v)) {car = keys_add(v, v, m);}
      keys_rs1(v);
      if (car) {v[DI - 1] |= 0x8000000000000000;}
    } else if (cmpResult > 0) {
      keys_sub(a, a, b);
      keys_rs1(a);
      if (keys_cmp(u, v) < 0) {keys_add(u, u, m);}
      keys_sub(u, u, v);
      if (!EVEN(u)) {car = keys_add(u, u, m);}
      keys_rs1(u);
      if (car) {u[DI - 1] |= 0x8000000000000000;}
    } else {
      keys_sub(b, b, a);
      keys_rs1(b);
      if (keys_cmp(v, u) < 0) {keys_add(v, v, m);}
      keys_sub(v, v, u);
      if (!EVEN(v)) {car = keys_add(v, v, m);}
      keys_rs1(v);
      if (car) {v[DI-1] |= 0x8000000000000000;}
    }
  }
  keys_set(r, u);
}

static void keys_p_mul(pt *r, pt *p, u64 *q, u64 *s) {
  u64 Rx[2][DI], Ry[2][DI], z[DI], nb;

  keys_set(Rx[1], p->x);
  keys_set(Ry[1], p->y);
  keys_p_inidoub(Rx[1], Ry[1], Rx[0], Ry[0], s);
  for (int i = keys_bits(q) - 2; i > 0; --i) {
    nb = !keys_chk(q, i);
    keys_p_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    keys_p_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  }
  nb = !keys_chk(q, 0);
  keys_p_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
  // Find final 1/Z value.
  printf("p_mul-----\n");
  keys_m_sub(z, Rx[1], Rx[0], curve_p);
  keys_m_mul(z, z, Ry[1-nb]);
    printf("p_mul-----\n");

  keys_m_mul(z, z, p->x);
      printf("p_mul-----------\n");

  keys_m_inv(z, z, curve_p);
  printf("p_mul-----\n");

  keys_m_mul(z, z, p->y);
  keys_m_mul(z, z, Rx[1-nb]);
    printf("-----p_mul-----\n");

  // End 1/Z calculation
  keys_p_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  keys_p_appz(Rx[0], Ry[0], z);
  keys_set(r->x, Rx[0]);
  keys_set(r->y, Ry[0]);
}

// Public functions

// Random
u32 prng_rotate(u32 x, u32 k) {return (x << k) | (x >> (32 - k));}

u32 prng_next(void) {
  u32 e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e;
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

void prng_init(u32 seed) {
  prng_ctx.a = 0xea7f00d1;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (u32 i = 0; i < 31; ++i) {(void)prng_next();}
}

// Make public key
int keys_make_keys(u64 publ[KB + 1], u64 priv[KB]) {
  u64 private[DI];
  pt public;
  do {
    // Make sure the private key is in the range [1, n-1].
    // For the supported curves, n is always large enough that we only need to
    // subtract once at most.
    if (keys_zero(private)) {continue;}
    if (keys_cmp(curve_n, private) != 1) {keys_sub(private, private, curve_n);}
    keys_p_mul(&public, &curve_g, private, NULL);
  } while(keys_p_zero(&public));
  keys_set(priv, private);
  keys_set(publ + 1, public.x);
  publ[0] = 2 + (public.y[0] & 0x01);
  return 1;
}

// create a secret from the public and private key
int keys_shar_secr(const u64 publ[KB + 1], const u64 priv[KB], u64 secr[KB]) {
  pt public, product;
  u64 private[DI], random[DI];

  keys_p_decom(&public, publ);
  keys_set(private, priv);
  keys_p_mul(&product, &public, private, random);
  keys_set(secr, product.x);
  return !keys_p_zero(&product);
}

