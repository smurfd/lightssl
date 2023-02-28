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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lightkeys.h"
#include "lightdefs.h"

//
// Clear a
static void lkeys_clear(uint64_t *a) {for (uint8_t i = 0; i < DI; ++i) {a[i] = 0;}}

//
// Check if a is zero, return 1, if not return 0
static int lkeys_zero(const uint64_t *a) {
  for (uint8_t i = 0; i < DI; ++i) {if (a[i]) {return 0;}}
  return 1;
}

//
// Check if bit a or b is set, if so return diff from zero
static uint64_t lkeys_chk(const uint64_t *a, const uint32_t b) {
  return (a[b / 64] & ((uint64_t)1 << (MOD(b, 64))));
}

//
// Count 64bit in a
static uint32_t lkeys_count(const uint64_t *a) {
  int i;

  for (i = DI - 1; i >= 0 && a[i] == 0; --i) {}
  return (i + 1);
}

//
// Set a from b
static void lkeys_set(uint64_t *a, const uint64_t *b) {
  for (uint8_t i = 0; i < DI; ++i) {a[i] = b[i];}
}

//
// Check number of bits needed for a
static uint32_t lkeys_bits(uint64_t *a) {
  uint32_t i, nd = lkeys_count(a); uint64_t d;

  if (nd == 0) return 0;
  nd--; d = a[nd];
  for (i = 0; d; ++i) d >>= 1;
  return ((nd) * 64 + i);
}

//
// Compare a and b
static int lkeys_cmp(const uint64_t *a, const uint64_t *b) {
  for (int i = DI-1; i >= 0; --i) {
    if (a[i] > b[i]) {return 1;} else if (a[i] < b[i]) {return -1;}
  }
  return 0;
}

//
// Left shift
static uint64_t lkeys_ls(uint64_t *a, const uint64_t *b, const uint32_t c) {
  uint64_t ovr = 0;

  for (uint8_t i = 0; i < DI; ++i) {
    uint64_t t = b[i]; a[i] = (t << c) | ovr;
    ovr = t >> (64 - c);
  }
  return ovr;
}

//
// Right shift by 1
static void lkeys_rs1(uint64_t *a) {
  uint64_t *e = a, ovr = 0;

  a += DI;
  while (a-- > e) {uint64_t t = *a; *a = (t >> 1) | ovr; ovr = t << 63;}
}

//
// Adds b and c
static uint64_t lkeys_add(uint64_t *a, const uint64_t *b, const uint64_t *c) {
  uint64_t ovr = 0;

  for (uint8_t i = 0; i < DI; ++i) {
    uint64_t s = b[i] + c[i] + ovr;
    if (s != b[i]) {ovr = (s < b[i]);} a[i] = s;
  }
  return ovr;
}

//
// Sub b and c
static uint64_t lkeys_sub(uint64_t *a, const uint64_t *b, const uint64_t *c) {
  uint64_t ovr = 0;

  for (uint8_t i = 0; i < DI; ++i) {
    uint64_t d = b[i] - c[i] - ovr;
    if (d != b[i]) {ovr = (d > b[i]);} a[i] = d;
  }
  return ovr;
}

//
//
static void akrr(uint64_t **a, uint64_t k, u128 *r, uint64_t *r2) {
  (*a)[k] = (uint64_t)(*r); (*r) = ((*r) >> 64) | (((u128)(*r2)) << 64); (*r2) = 0;
}

//
// Multiply
static void lkeys_mul(uint64_t *a, const uint64_t *b, const uint64_t *c) {
  u128 r = 0; uint64_t r2 = 0, di22 = DI * 2 - 1;

  for (uint8_t k = 0; k < di22; ++k) {
    uint32_t min = (k < DI ? 0 : (k + 1) - DI);
    for (uint8_t j = min; j <= k && j < DI; ++j) {
      u128 p = (u128)b[j] * c[k - j]; // product
      r += p; r2 += (r < p);
    }
    akrr(&a, k, &r, &r2);
  }
  a[di22] = (uint64_t)r;
}

//
// Square
static void lkeys_sqr(uint64_t *a, const uint64_t *b) {
  u128 r = 0; uint64_t r2 = 0, di22 = DI * 2 - 1;

  for (uint8_t k = 0; k < di22; ++k) {
    uint32_t min = (k < DI ? 0 : (k + 1) - DI);
    for (uint8_t j = min; j <= k && j <= k - j; ++j) {
      u128 p = (u128)b[j] * b[k - j]; // product
      if (j < k - j) {r2 += p >> 127; p *= 2;}
      r += p; r2 += (r < p);
    }
    akrr(&a, k, &r, &r2);
  }
  a[di22] = (uint64_t)r;
}

//
//
static void lkeys_o_mul(uint64_t *a, const uint64_t *b) {
  uint64_t t[DI], ovr;

  lkeys_set(a, b);
  ovr = lkeys_ls(t, b, 32);
  a[DI + 1] = ovr + lkeys_add(a + 1, a + 1, t);
  a[DI + 2] = lkeys_add(a + 2, a + 2, b);
  ovr += lkeys_sub(a, a, t);
  uint64_t d = a[DI] - ovr;
  if (d > a[DI]) {
    for (uint8_t i = 1+DI; ; ++i) {--a[i]; if (a[i] != (uint64_t) - 1) {break;}}
  }
  a[DI] = d;
}

// Modulo functions

//
// Modulo add
static void lkeys_m_add(uint64_t *a, const uint64_t *b, const uint64_t *c,
  const uint64_t *m) {
  uint64_t ovr = lkeys_add(a, b, c);

  if (ovr || lkeys_cmp(a, m) >= 0) {lkeys_sub(a, a, m);}
}

//
// Modulo sub
static void lkeys_m_sub(uint64_t *a, const uint64_t *b, const uint64_t *c,
  const uint64_t *m) {
  if (lkeys_sub(a, b, c)) {lkeys_add(a, a, m);}
}

//
// Modulo mod
static void lkeys_m_mod(uint64_t *a, uint64_t *b) {
  uint64_t t[DI2];

  while (!lkeys_zero(b + DI)) {
    uint64_t ovr = 0;
    lkeys_clear(t); lkeys_clear(t + DI);
    lkeys_o_mul(t, b + DI);
    lkeys_clear(b + DI);
    for (uint8_t i = 0; i < DI + 3; ++i) {
      uint64_t s = b[i] + t[i] + ovr;
      if (s != b[i]) {ovr = (s < b[i]);}
      b[i] = s;
    }
  }
  while (lkeys_cmp(b, curve_p) > 0) {lkeys_sub(b, b, curve_p);}
  lkeys_set(a, b);
}

//
// Modulo multiply
static void lkeys_m_mul(uint64_t *a, const uint64_t *b, const uint64_t *c) {
  uint64_t p[DI2]; lkeys_mul(p, b, c); lkeys_m_mod(a, p);
}

//
// Modulo square
static void lkeys_m_sqr(uint64_t *a, const uint64_t *b) {
  uint64_t p[DI2]; lkeys_sqr(p, b); lkeys_m_mod(a, p);
}

//
// Modulo square root
static void lkeys_m_sqrt(uint64_t a[DI]) {
  uint64_t p1[DI] = {1}, r[DI] = {1};

  lkeys_add(p1, curve_p, p1);
  for (uint32_t i = lkeys_bits(p1) - 1; i > 1; --i) {
    lkeys_m_sqr(r, r);
    if (lkeys_chk(p1, i)) {lkeys_m_mul(r, r, a);}
  }
  lkeys_set(a, r);
}

//
//
static void lkeys_m_mmul(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *m) {
  uint64_t p[DI2], mm[DI2];
  uint32_t ds, bs, pb, mb = lkeys_bits(m);

  lkeys_mul(p, b, c);
  pb = lkeys_bits(p + DI);
  if (pb) {pb += DI * 64;}
  else {pb = lkeys_bits(p);};
  if (pb < mb) {lkeys_set(a, p); return;}

  lkeys_clear(mm); lkeys_clear(mm + DI);
  ds = (pb - mb) / 64; bs = MOD(pb - mb, 64);
  if (bs) {mm[ds + DI] = lkeys_ls(mm + ds, m, bs);}
  else {lkeys_set(mm + ds, m);}

  lkeys_clear(a); a[0] = 1;
  while (pb > DI * 64 || lkeys_cmp(mm, m) >= 0) {
    int cmp = lkeys_cmp(DI + mm, DI + p);
    if (cmp < 0 || (cmp == 0 && lkeys_cmp(mm, p) <= 0)) {
      if (lkeys_sub(p, p, mm)) {lkeys_sub(DI + p, DI + p, a);}
      lkeys_sub(DI + p, DI + p, DI + mm);
    }
    uint64_t ovr = (mm[DI] & 0x01) << 63;
    lkeys_rs1(DI + mm); lkeys_rs1(mm);
    mm[DI - 1] |= ovr;
    --pb;
  }
  lkeys_set(a, p);
}

// Points functions

//
// Points is this zero?
static int lkeys_p_zero(pt *a) {return (lkeys_zero(a->x) && lkeys_zero(a->y));}

//
// Points double
static void lkeys_p_double(uint64_t *a, uint64_t *b, uint64_t *c) {
  uint64_t t4[DI], t5[DI];

  if (lkeys_zero(c)) {return;}
  lkeys_m_sqr(t4, b);
  lkeys_m_mul(t5, a, t4);
  lkeys_m_sqr(t4, t4);
  lkeys_m_mul(b, b, c);
  lkeys_m_sqr(c, c);

  lkeys_m_add(a, a, c, curve_p);
  lkeys_m_add(c, c, c, curve_p);
  lkeys_m_sub(c, a, c, curve_p);
  lkeys_m_mul(a, a, c);

  lkeys_m_add(c, a, a, curve_p);
  lkeys_m_add(a, a, c, curve_p);
  if (lkeys_chk(a, 0)) {
    uint64_t ovr = lkeys_add(a, a, curve_p);
    lkeys_rs1(a);
    a[DI - 1] |= ovr << 63;
  } else {lkeys_rs1(a);}
  lkeys_m_sqr(c, a);
  lkeys_m_sub(c, c, t5, curve_p);
  lkeys_m_sub(c, c, t5, curve_p);
  lkeys_m_sub(t5, t5, c, curve_p);
  lkeys_m_mul(a, a, t5);
  lkeys_m_sub(t4, a, t4, curve_p);
  lkeys_set(a, c);
  lkeys_set(c, b);
  lkeys_set(b, t4);
}

//
//
static void lkeys_p_decom(pt *a, const uint64_t b[KB + 1]) {
  uint64_t tr[DI] = {3};

  lkeys_set(a->x, b + 1);
  lkeys_m_sqr(a->y, a->x);
  lkeys_m_sub(a->y, a->y, tr, curve_p);
  lkeys_m_mul(a->y, a->y, a->x);
  lkeys_m_add(a->y, a->y, curve_b, curve_p);
  lkeys_m_sqrt(a->y);
  if ((a->y[0] & 0x01) != (b[0] & 0x01)) {lkeys_sub(a->y, curve_p, a->y);}
}

//
// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
static void lkeys_p_appz(uint64_t *a, uint64_t *b, const uint64_t *z) {
  uint64_t t[DI];

  lkeys_m_sqr(t, z);
  lkeys_m_mul(a, a, t);
  lkeys_m_mul(t, t, z);
  lkeys_m_mul(b, b, t);
}

//
// P = (x1, y1) => 2P, (x2, y2) => P'
static void lkeys_p_inidoub(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d,
  uint64_t *p) {
  uint64_t z[DI];

  lkeys_set(c, a); lkeys_set(d, b);
  lkeys_clear(z); z[0] = 1;
  if (p) {lkeys_set(z, p);}
  lkeys_p_appz(a, b, z);
  lkeys_p_double(a, b, z);
  lkeys_p_appz(c, d, z);
}

//
// Points add
static void lkeys_p_add(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
  uint64_t t5[DI];

  lkeys_m_sub(t5, c, a, curve_p);
  lkeys_m_sqr(t5, t5);
  lkeys_m_mul(a, a, t5);
  lkeys_m_mul(c, c, t5);
  lkeys_m_sub(d, d, b, curve_p);
  lkeys_m_sqr(t5, d);

  lkeys_m_sub(t5, t5, a, curve_p);
  lkeys_m_sub(t5, t5, c, curve_p);
  lkeys_m_sub(c, c, a, curve_p);
  lkeys_m_mul(b, b, c);
  lkeys_m_sub(c, a, t5, curve_p);
  lkeys_m_mul(d, d, c);
  lkeys_m_sub(d, d, b, curve_p);
  lkeys_set(c, t5);
}

//
// Points add
static void lkeys_p_addc(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  uint64_t t5[DI], t6[DI], t7[DI];

  lkeys_m_sub(t5, c, a, curve_p);
  lkeys_m_sqr(t5, t5);
  lkeys_m_mul(a, a, t5);
  lkeys_m_mul(c, c, t5);
  lkeys_m_add(t5, d, b, curve_p);
  lkeys_m_sub(d, d, b, curve_p);

  lkeys_m_sub(t6, c, a, curve_p);
  lkeys_m_mul(b, b, t6);
  lkeys_m_add(t6, a, c, curve_p);
  lkeys_m_sqr(c, d);
  lkeys_m_sub(c, c, t6, curve_p);

  lkeys_m_sub(t7, a, c, curve_p);
  lkeys_m_mul(d, d, t7);
  lkeys_m_sub(d, d, b, curve_p);

  lkeys_m_sqr(t7, t5);
  lkeys_m_sub(t7, t7, t6, curve_p);
  lkeys_m_sub(t6, t7, a, curve_p);
  lkeys_m_mul(t6, t6, t5);
  lkeys_m_sub(b, t6, b, curve_p);
  lkeys_set(a, t7);
}

//
// Modulo inversion
static void lkeys_m_inv(uint64_t *r, uint64_t *p, uint64_t *m) {
  uint64_t a[DI], b[DI], u[DI], v[DI], car, x8 = 0x8000000000000000;
  int cmpResult;

  if(lkeys_zero(p)) {lkeys_clear(r); return;}
  lkeys_set(a, p);
  lkeys_set(b, m);
  lkeys_clear(u); u[0] = 1;
  lkeys_clear(v);
  while ((cmpResult = lkeys_cmp(a, b)) != 0) {
    car = 0;
    if (EVEN(a)) {
      lkeys_rs1(a); if (!EVEN(u)) {car = lkeys_add(u, u, m);}
      lkeys_rs1(u); if (car) {u[DI - 1] |= x8;}
    } else if (EVEN(b)) {
      lkeys_rs1(b); if (!EVEN(v)) {car = lkeys_add(v, v, m);}
      lkeys_rs1(v); if (car) {v[DI - 1] |= x8;}
    } else if (cmpResult > 0) {
      lkeys_sub(a, a, b);
      lkeys_rs1(a); if (lkeys_cmp(u, v) < 0) {lkeys_add(u, u, m);}
      lkeys_sub(u, u, v); if (!EVEN(u)) {car = lkeys_add(u, u, m);}
      lkeys_rs1(u); if (car) {u[DI - 1] |= x8;}
    } else {
      lkeys_sub(b, b, a);
      lkeys_rs1(b); if (lkeys_cmp(v, u) < 0) {lkeys_add(v, v, m);}
      lkeys_sub(v, v, u); if (!EVEN(v)) {car = lkeys_add(v, v, m);}
      lkeys_rs1(v); if (car) {v[DI - 1] |= x8;}
    }
  }
  lkeys_set(r, u);
}

//
// Point multiplication
static void lkeys_p_mul(pt *r, pt *p, uint64_t *q, uint64_t *s) {
  uint64_t Rx[2][DI], Ry[2][DI], z[DI];

  lkeys_set(Rx[1], p->x); lkeys_set(Ry[1], p->y);
  lkeys_p_inidoub(Rx[1], Ry[1], Rx[0], Ry[0], s);
  for (int i = lkeys_bits(q) - 2; i > 0; --i) {
    int nb = !lkeys_chk(q, i);
    lkeys_p_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
    lkeys_p_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
  }
  int nb = !lkeys_chk(q, 0);
  lkeys_p_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
  // Find final 1/Z value.
  lkeys_m_sub(z, Rx[1], Rx[0], curve_p);
  lkeys_m_mul(z, z, Ry[1 - nb]);
  lkeys_m_mul(z, z, p->x);
  lkeys_m_inv(z, z, curve_p);
  lkeys_m_mul(z, z, p->y);
  lkeys_m_mul(z, z, Rx[1 - nb]);

  // End 1/Z calculation
  lkeys_p_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  lkeys_p_appz(Rx[0], Ry[0], z);
  lkeys_set(r->x, Rx[0]); lkeys_set(r->y, Ry[0]);
}

//
// Random rotate
static uint64_t lkeys_rnd_rotate(uint64_t x, uint64_t k) {
  return (x << k) | (x >> (32 - k));
}

//
// Random next
uint64_t lkeys_rnd_next(void) {
  uint64_t e = prng_ctx.a - lkeys_rnd_rotate(prng_ctx.b, 27);

  prng_ctx.a = prng_ctx.b ^ lkeys_rnd_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

//
// Random init
void lkeys_rnd_init(uint64_t seed) {
  prng_ctx.a = 0xea7f00d1; prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (uint64_t i = 0; i < 31; ++i) {(void)lkeys_rnd_next();}
}

//
// Make public key
int lkeys_make_keys(uint64_t publ[KB + 1], uint64_t priv[KB]) {
  uint64_t private[DI], x = 1; // range [1, n-1]
  pt public;

  while(x) {
    if (lkeys_zero(private)) {continue;}
    if (lkeys_cmp(curve_n, private) != 1) {lkeys_sub(private, private, curve_n);}
    lkeys_p_mul(&public, &curve_g, private, NULL);
    x = lkeys_p_zero(&public);
  }
  lkeys_set(priv, private);
  lkeys_set(publ + 1, public.x);
  publ[0] = 2 + (public.y[0] & 0x01);
  return 1;
}

//
// create a secret from the public and private key
int lkeys_shar_secr(const uint64_t publ[KB + 1], const uint64_t priv[KB],
  uint64_t secr[KB]) {
  pt public, product;
  uint64_t private[DI], random[DI];

  lkeys_p_decom(&public, publ);
  lkeys_set(private, priv);
  lkeys_p_mul(&product, &public, private, random);
  lkeys_set(secr, product.x);
  return !lkeys_p_zero(&product);
}

//
// Create signature
int lkeys_sign(const uint64_t priv[KB], const uint64_t hash[KB],
    uint64_t sign[KB2]) {
  uint64_t k[DI], tmp[DI], s[DI], x = 1;
  pt p;

  while (x) {
    if (lkeys_zero(k)) {continue;}
    if (lkeys_cmp(curve_n, k) != 1) {lkeys_sub(k, k, curve_n);}
    lkeys_p_mul(&p, &curve_g, k, NULL);
    if (lkeys_cmp(curve_n, p.x) != 1) {lkeys_sub(p.x, p.x, curve_n);}
    x = lkeys_zero(p.x);
  }
  lkeys_set(tmp, priv);
  lkeys_m_mmul(s, p.x, tmp, curve_n);
  lkeys_set(tmp, hash);
  lkeys_m_add(s, tmp, s, curve_n);
  lkeys_m_inv(k, k, curve_n);
  lkeys_m_mmul(s, s, k, curve_n);
  lkeys_set(sign, p.x);
  lkeys_set(sign + KB, s);
  return 1;
}

//
// Verify signature
int lkeys_vrfy(const uint64_t publ[KB + 1], const uint64_t hash[KB],
    const uint64_t sign[KB2]) {
  uint64_t tx[DI], ty[DI], tz[DI],r[DI],s[DI],u1[DI],u2[DI],z[DI],rx[DI],ry[DI];
  pt public, sum;

  lkeys_p_decom(&public, publ);
  lkeys_set(r, sign);
  lkeys_set(s, sign + KB);
  if (lkeys_zero(r) || lkeys_zero(s)) {return 0;}
  if (lkeys_cmp(curve_n, r) != 1 || lkeys_cmp(curve_n, s) != 1) {return 0;}
  lkeys_m_inv(z, s, curve_n);
  lkeys_set(u1, hash);
  lkeys_m_mmul(u1, u1, z, curve_n);
  lkeys_m_mmul(u2, r, z, curve_n);

  // Calculate sum = G + Q.
  lkeys_set(sum.x, public.x); lkeys_set(sum.y, public.y);
  lkeys_set(tx, curve_g.x); lkeys_set(ty, curve_g.y);
  lkeys_m_sub(z, sum.x, tx, curve_p);
  lkeys_p_add(tx, ty, sum.x, sum.y);
  lkeys_m_inv(z, z, curve_p);
  lkeys_p_appz(sum.x, sum.y, z);

  // Use Shamir's trick to calculate u1*G + u2*Q
  pt *points[4] = {NULL, &curve_g, &public, &sum};
  uint32_t nb = (lkeys_bits(u1) > lkeys_bits(u2) ? lkeys_bits(u1) : lkeys_bits(u2));
  pt *point = points[(!!lkeys_chk(u1, nb - 1)) | ((!!lkeys_chk(u2, nb - 1)) << 1)];

  lkeys_set(rx, point->x);
  lkeys_set(ry, point->y);
  lkeys_clear(z);
  z[0] = 1;
  for (int i = nb - 2; i >= 0; --i) {
    lkeys_p_double(rx, ry, z);
    int index = (!!lkeys_chk(u1, i)) | ((!!lkeys_chk(u2, i)) << 1);
    pt *point = points[index];
    if (point) {
      lkeys_set(tx, point->x); lkeys_set(ty, point->y);
      lkeys_p_appz(tx, ty, z);
      lkeys_m_sub(tz, rx, tx, curve_p);
      lkeys_p_add(tx, ty, rx, ry);
      lkeys_m_mul(z, z, tz);
    }
  }
  lkeys_m_inv(z, z, curve_p);
  lkeys_p_appz(rx, ry, z);
  if (lkeys_cmp(curve_n, rx) != 1) {lkeys_sub(rx, rx, curve_n);}
  return (lkeys_cmp(rx, r) == 0);
}
