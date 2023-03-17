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
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "lightkeys.h"
#include "lightdefs.h"

//
// Clear a
static void lkclear(uint64_t *a) {for (uint8_t i = 0; i < DI; ++i) {a[i] = 0;}}

//
// Check if a is zero, return 1, if not return 0
static int lkzero(const uint64_t *a) {
  for (uint8_t i = 0; i < DI; ++i) {if (a[i]) {return 0;}}
  return 1;
}

//
// Check if bit a or b is set, if so return diff from zero
static uint64_t lkchk(const uint64_t *a, const uint32_t b) {
  return (a[b / 64] & ((uint64_t)1 << (MOD(b, 64))));
}

//
// Count 64bit in a
static uint32_t lkcount(const uint64_t *a) {
  int i;
  for (i = DI - 1; i >= 0 && a[i] == 0; --i) {}
  return (i + 1);
}

//
// Set a from b
static void lkset(uint64_t *a, const uint64_t *b) {
  for (uint8_t i = 0; i < DI; ++i) {a[i] = b[i];}
}

//
// Check number of bits needed for a
static uint32_t lkbits(uint64_t *a) {
  uint32_t i, nd = lkcount(a); uint64_t d;

  if (nd == 0) return 0;
  nd--; d = a[nd];
  for (i = 0; d; ++i) d >>= 1;
  return ((nd) * 64 + i);
}

//
// Compare a and b
static int lkcmp(const uint64_t *a, const uint64_t *b) {
  for (int i = DI-1; i >= 0; --i) {
    if (a[i] > b[i]) {return 1;}
    else if (a[i] < b[i]) {return -1;}
  }
  return 0;
}

//
// Left shift
static uint64_t lkls(uint64_t *a, const uint64_t *b, const uint32_t c) {
  uint64_t ovr = 0;

  for (uint8_t i = 0; i < DI; ++i) {
    uint64_t t = b[i]; a[i] = (t << c) | ovr;
    ovr = t >> (64 - c);
  }
  return ovr;
}

//
// Right shift by 1
static void lkrs1(uint64_t *a) {
  uint64_t *e = a, ovr = 0;

  a += DI;
  while (a-- > e) {uint64_t t = *a; *a = (t >> 1) | ovr; ovr = t << 63;}
}

//
// Adds b and c
static uint64_t lkadd(uint64_t *a, const uint64_t *b, const uint64_t *c) {
  uint64_t ovr = 0;

  for (uint8_t i = 0; i < DI; ++i) {
    uint64_t s = b[i] + c[i] + ovr;
    if (s != b[i]) {ovr = (s < b[i]);} a[i] = s;
  }
  return ovr;
}

//
// Sub b and c
static uint64_t lksub(uint64_t *a, const uint64_t *b, const uint64_t *c) {
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
static void lkmul(uint64_t *a, const uint64_t *b, const uint64_t *c) {
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
static void lksqr(uint64_t *a, const uint64_t *b) {
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
static void lko_mul(uint64_t *a, const uint64_t *b) {
  lkset(a, b);
  uint64_t t[DI] = {0}, ovr = lkls(t, b, 32);
  a[DI + 1] = ovr + lkadd(a + 1, a + 1, t);
  a[DI + 2] = lkadd(a + 2, a + 2, b);
  ovr += lksub(a, a, t);
  uint64_t d = a[DI] - ovr;
  if (d > a[DI]) {
    for (uint8_t i = 1+DI; ; ++i) {--a[i]; if (a[i] != (uint64_t) - 1) {break;}}
  }
  a[DI] = d;
}

// Modulo functions
//
// Modulo add
static void lkm_add(uint64_t *a, const uint64_t *b, const uint64_t *c, const uint64_t *m) {
  if (lkadd(a, b, c) || lkcmp(a, m) >= 0) {lksub(a, a, m);}
}

//
// Modulo sub
static void lkm_sub(uint64_t *a, const uint64_t *b, const uint64_t *c, const uint64_t *m) {
  if (lksub(a, b, c)) {lkadd(a, a, m);}
}

//
// Modulo mod
static void lkm_mod(uint64_t *a, uint64_t *b) {
  while (!lkzero(b + DI)) {
    uint64_t ovr = 0, t[DI2] = {0};
    lkclear(t); lkclear(t + DI);
    lko_mul(t, b + DI);
    lkclear(b + DI);
    for (uint8_t i = 0; i < DI + 3; ++i) {
      uint64_t s = b[i] + t[i] + ovr;
      if (s != b[i]) {ovr = (s < b[i]);}
      b[i] = s;
    }
  }
  while (lkcmp(b, curve_p) > 0) {lksub(b, b, curve_p);}
  lkset(a, b);
}

//
// Modulo multiply
static void lkm_mul(uint64_t *a, const uint64_t *b, const uint64_t *c) {
  uint64_t p[DI2] = {0};

  lkmul(p, b, c); lkm_mod(a, p);
}

//
// Modulo square
static void lkm_sqr(uint64_t *a, const uint64_t *b) {
  uint64_t p[DI2] = {0};

  lksqr(p, b); lkm_mod(a, p);
}

//
// Modulo square root
static void lkm_sqrt(uint64_t a[DI]) {
  uint64_t p1[DI] = {1}, r[DI] = {1};

  lkadd(p1, curve_p, p1);
  for (uint32_t i = lkbits(p1) - 1; i > 1; --i) {
    lkm_sqr(r, r);
    if (lkchk(p1, i)) {lkm_mul(r, r, a);}
  }
  lkset(a, r);
}

//
//
static void lkm_mmul(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *m) {
  uint32_t ds, bs, pb, mb = lkbits(m);
  uint64_t p[DI2] = {0}, mm[DI2] = {0};

  lkmul(p, b, c);
  pb = lkbits(p + DI);
  if (pb) {pb += DI * 64;}
  else {pb = lkbits(p);};
  if (pb < mb) {lkset(a, p); return;}

  lkclear(mm); lkclear(mm + DI);
  ds = (pb - mb) / 64; bs = MOD(pb - mb, 64);
  if (bs) {mm[ds + DI] = lkls(mm + ds, m, bs);}
  else {lkset(mm + ds, m);}

  lkclear(a); a[0] = 1;
  while (pb > DI * 64 || lkcmp(mm, m) >= 0) {
    int cmp = lkcmp(DI + mm, DI + p);
    if (cmp < 0 || (cmp == 0 && lkcmp(mm, p) <= 0)) {
      if (lksub(p, p, mm)) {lksub(DI + p, DI + p, a);}
      lksub(DI + p, DI + p, DI + mm);
    }
    uint64_t ovr = (mm[DI] & 0x01) << 63;
    lkrs1(DI + mm); lkrs1(mm);
    mm[DI - 1] |= ovr;
    --pb;
  }
  lkset(a, p);
}

// Points functions
//
// Points is this zero?
static int lkp_zero(pt *a) {return (lkzero(a->x) && lkzero(a->y));}

//
// Points double
static void lkp_double(uint64_t *a, uint64_t *b, uint64_t *c) {
  uint64_t t4[DI] = {0}, t5[DI] = {0};

  if (lkzero(c)) {return;}
  lkm_sqr(t4, b); lkm_mul(t5, a, t4); lkm_sqr(t4, t4);
  lkm_mul(b, b, c); lkm_sqr(c, c);

  lkm_add(a, a, c, curve_p); lkm_add(c, c, c, curve_p);
  lkm_sub(c, a, c, curve_p); lkm_mul(a, a, c);

  lkm_add(c, a, a, curve_p); lkm_add(a, a, c, curve_p);
  if (lkchk(a, 0)) {
    uint64_t ovr = lkadd(a, a, curve_p);
    lkrs1(a);
    a[DI - 1] |= ovr << 63;
  } else {lkrs1(a);}
  lkm_sqr(c, a); lkm_sub(c, c, t5, curve_p); lkm_sub(c, c, t5, curve_p);
  lkm_sub(t5, t5, c, curve_p); lkm_mul(a, a, t5); lkm_sub(t4, a, t4, curve_p);
  lkset(a, c); lkset(c, b); lkset(b, t4);
}

//
//
static void lkp_decom(pt *a, const uint64_t b[KB + 1]) {
  uint64_t tr[DI] = {3};

  lkset(a->x, b + 1);
  lkm_sqr(a->y, a->x);
  lkm_sub(a->y, a->y, tr, curve_p);
  lkm_mul(a->y, a->y, a->x);
  lkm_add(a->y, a->y, curve_b, curve_p);
  lkm_sqrt(a->y);
  if ((a->y[0] & 0x01) != (b[0] & 0x01)) {lksub(a->y, curve_p, a->y);}
}

//
// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
static void lkp_appz(uint64_t *a, uint64_t *b, const uint64_t *z) {
  uint64_t t[DI] = {0};

  lkm_sqr(t, z); lkm_mul(a, a, t); lkm_mul(t, t, z); lkm_mul(b, b, t);
}

//
// P = (x1, y1) => 2P, (x2, y2) => P'
static void lkp_inidoub(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d, uint64_t *p) {
  uint64_t z[DI] = {0};

  lkset(c, a); lkset(d, b);
  lkclear(z); z[0] = 1;
  if (p) {lkset(z, p);}
  lkp_appz(a, b, z); lkp_double(a, b, z); lkp_appz(c, d, z);
}

//
// Points add
static void lkp_add(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
  uint64_t t5[DI] = {0};

  lkm_sub(t5, c, a, curve_p); lkm_sqr(t5, t5);
  lkm_mul(a, a, t5); lkm_mul(c, c, t5); lkm_sub(d, d, b, curve_p);
  lkm_sqr(t5, d);

  lkm_sub(t5, t5, a, curve_p); lkm_sub(t5, t5, c, curve_p);
  lkm_sub(c, c, a, curve_p); lkm_mul(b, b, c); lkm_sub(c, a, t5, curve_p);
  lkm_mul(d, d, c); lkm_sub(d, d, b, curve_p); lkset(c, t5);
}

//
// Points add
static void lkp_addc(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  uint64_t t5[DI] = {0}, t6[DI] = {0}, t7[DI] = {0};

  lkm_sub(t5, c, a, curve_p); lkm_sqr(t5, t5); lkm_mul(a, a, t5);
  lkm_mul(c, c, t5); lkm_add(t5, d, b, curve_p); lkm_sub(d, d, b, curve_p);

  lkm_sub(t6, c, a, curve_p); lkm_mul(b, b, t6); lkm_add(t6, a, c, curve_p);
  lkm_sqr(c, d); lkm_sub(c, c, t6, curve_p);

  lkm_sub(t7, a, c, curve_p); lkm_mul(d, d, t7); lkm_sub(d, d, b, curve_p);

  lkm_sqr(t7, t5); lkm_sub(t7, t7, t6, curve_p); lkm_sub(t6, t7, a, curve_p);
  lkm_mul(t6, t6, t5); lkm_sub(b, t6, b, curve_p); lkset(a, t7);
}

//
// Modulo inversion
static void lkm_inv(uint64_t *r, uint64_t *p, uint64_t *m) {
  uint64_t a[DI] = {0}, b[DI] = {0}, u[DI] = {0}, v[DI] = {0}, car;
  int cmpResult;

  if(lkzero(p)) {lkclear(r); return;}
  lkset(a, p); lkset(b, m);
  lkclear(u); u[0] = 1; lkclear(v);
  while ((cmpResult = lkcmp(a, b)) != 0) {
    car = 0;
    if (EVEN(a)) {
      lkrs1(a);
      if (!EVEN(u)) {car = lkadd(u, u, m);}
      lkrs1(u);
      if (car) {u[DI - 1] |= 0x8000000000000000;}
    } else if (EVEN(b)) {
      lkrs1(b);
      if (!EVEN(v)) {car = lkadd(v, v, m);}
      lkrs1(v);
      if (car) {v[DI - 1] |= 0x8000000000000000;}
    } else if (cmpResult > 0) {
      lksub(a, a, b); lkrs1(a);
      if (lkcmp(u, v) < 0) {lkadd(u, u, m);}
      lksub(u, u, v);
      if (!EVEN(u)) {car = lkadd(u, u, m);}
      lkrs1(u);
      if (car) {u[DI - 1] |= 0x8000000000000000;}
    } else {
      lksub(b, b, a); lkrs1(b);
      if (lkcmp(v, u) < 0) {lkadd(v, v, m);}
      lksub(v, v, u);
      if (!EVEN(v)) {car = lkadd(v, v, m);}
      lkrs1(v);
      if (car) {v[DI-1] |= 0x8000000000000000;}
    }
  }
  lkset(r, u);
}

//
// Point multiplication
static void lkp_mul(pt *r, pt *p, uint64_t *q, uint64_t *s) {
  uint64_t Rx[2][DI], Ry[2][DI], z[DI] = {0};
  int nb;

  lkset(Rx[1], p->x); lkset(Ry[1], p->y);
  lkp_inidoub(Rx[1], Ry[1], Rx[0], Ry[0], s);
  for (int i = lkbits(q) - 2; i > 0; --i) {
    nb = !lkchk(q, i);
    lkp_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    lkp_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  }
  nb = !lkchk(q, 0);
  lkp_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
  // Find final 1/Z value.
  lkm_sub(z, Rx[1], Rx[0], curve_p);
  lkm_mul(z, z, Ry[1-nb]); lkm_mul(z, z, p->x);
  lkm_inv(z, z, curve_p); lkm_mul(z, z, p->y); lkm_mul(z, z, Rx[1-nb]);

  // End 1/Z calculation
  lkp_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]); lkp_appz(Rx[0], Ry[0], z);
  lkset(r->x, Rx[0]); lkset(r->y, Ry[0]);
}

// Public functions
//
// Random rotate
uint64_t prng_rotate(uint64_t x, uint64_t k) {return (x << k) | (x >> (32 - k));}

//
// Random next
uint64_t prng_next(void) {
  uint64_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);

  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

//
// Random init
void prng_init(uint64_t seed) {
  prng_ctx.a = 0xea7f00d1; prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (uint64_t i = 0; i < 31; ++i) {(void)prng_next();}
}

//
// Make public key
int lkmake_keys(uint64_t publ[KB + 1], uint64_t priv[KB]) {
  uint64_t private[DI], co = 1; // range [1, n-1]
  pt public;

  while(co) {
    if (lkzero(private)) {continue;}
    if (lkcmp(curve_n, private) != 1) {lksub(private, private, curve_n);}
    lkp_mul(&public, &curve_g, private, NULL);
    co = lkp_zero(&public);
  }
  lkset(priv, private); lkset(publ + 1, public.x);
  publ[0] = 2 + (public.y[0] & 0x01);
  return 1;
}

//
// create a secret from the public and private key
int lkshar_secr(const uint64_t publ[KB + 1], const uint64_t priv[KB], uint64_t secr[KB]) {
  uint64_t private[DI] = {0}, random[DI] = {0};
  pt public, product;

  lkp_decom(&public, publ);
  lkset(private, priv);
  lkp_mul(&product, &public, private, random);
  lkset(secr, product.x);
  return lkp_zero(&product);
}

//
// Create signature
int lksign(const uint64_t priv[KB], const uint64_t hash[KB], uint64_t sign[KB2]) {
  uint64_t k[DI], tmp[DI], s[DI], co = 1;
  pt p;

  while (co) {
    if (lkzero(k)) {continue;}
    if (lkcmp(curve_n, k) != 1) {lksub(k, k, curve_n);}
    lkp_mul(&p, &curve_g, k, NULL);
    if (lkcmp(curve_n, p.x) != 1) {lksub(p.x, p.x, curve_n);}
    co = lkzero(p.x);
  }
  lkset(tmp, priv); lkm_mmul(s, p.x, tmp, curve_n);
  lkset(tmp, hash); lkm_add(s, tmp, s, curve_n);
  lkm_inv(k, k, curve_n); lkm_mmul(s, s, k, curve_n);
  lkset(sign, p.x); lkset(sign + KB, s);
  return 1;
}

//
// Verify signature
int lkvrfy(const uint64_t publ[KB + 1], const uint64_t hash[KB], const uint64_t sign[KB2]) {
  uint64_t tx[DI]={0}, ty[DI]={0}, tz[DI]={0}, r[DI]={0}, s[DI]={0}, u1[DI]={0}, u2[DI]={0}, z[DI]={0}, rx[DI]={0}, ry[DI]={0};
  pt public, sum;

  for (int j = 0; j < DI; j++)
    printf("vrfy01: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  lkp_decom(&public, publ);
  lkset(r, sign);
  lkset(s, sign + KB);
  for (int j = 0; j < DI; j++)
    printf("vrfy02: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");

  if (lkzero(r) || lkzero(s)) {return 0;}
  if (lkcmp(curve_n, r) != 1 || lkcmp(curve_n, s) != 1) {return 0;}
  lkm_inv(z, s, curve_n);
  lkset(u1, hash);
  for (int j = 0; j < DI; j++)
    printf("vrfy03: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  lkm_mmul(u1, u1, z, curve_n); lkm_mmul(u2, r, z, curve_n);

  // Calculate sum = G + Q.
  lkset(sum.x, public.x); lkset(sum.y, public.y);
  lkset(tx, curve_g.x); lkset(ty, curve_g.y);
  for (int j = 0; j < DI; j++)
    printf("vrfy04: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  lkm_sub(z, sum.x, tx, curve_p); lkp_add(tx, ty, sum.x, sum.y);
  for (int j = 0; j < DI; j++)
    printf("vrfy05: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  lkm_inv(z, z, curve_p); lkp_appz(sum.x, sum.y, z);
  for (int j = 0; j < DI; j++)
    printf("vrfy06: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  // Use Shamir's trick to calculate u1*G + u2*Q
  pt *points[4] = {NULL, &curve_g, &public, &sum};
  uint32_t nb = (lkbits(u1) > lkbits(u2) ? lkbits(u1) : lkbits(u2));
  pt *point = points[(!!lkchk(u1, nb - 1)) | ((!!lkchk(u2, nb - 1)) << 1)];

  lkset(rx, point->x); lkset(ry, point->y); lkclear(z);
  z[0] = 1;
  for (int j = 0; j < DI; j++)
    printf("vrfy07: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  for (int i = nb - 2; i >= 0; --i) {
    lkp_double(rx, ry, z);
    int index = (!!lkchk(u1, i)) | ((!!lkchk(u2, i)) << 1);
    pt *point = points[index];
    if (point) {
      lkset(tx, point->x); lkset(ty, point->y);
      lkp_appz(tx, ty, z); lkm_sub(tz, rx, tx, curve_p);
      lkp_add(tx, ty, rx, ry); lkm_mul(z, z, tz);
    }
  }
  for (int j = 0; j < DI; j++)
    printf("vrfy08: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");

  lkm_inv(z, z, curve_p); lkp_appz(rx, ry, z);
  if (lkcmp(curve_n, rx) != 1) {lksub(rx, rx, curve_n);}
  for (int j = 0; j < DI; j++)
    printf("vrfy09: %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu, %20llu\n",
        publ[j], hash[j], sign[j], public.x[j], r[j], s[j], z[j], u1[j], u2[j], sum.x[j], sum.y[j], tx[j], ty[j]);
  printf("-----------------\n");
  return (lkcmp(rx, r) == 0);
}
