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
// Imitate pythons %. -1 % 5 = 4, not -1
static int mod(const int n, const int m) {return ((n % m) + m) % m;}

//
// Clear a
static void keys_clear(u64 *a) {for (u08 i = 0; i < DI; ++i) {a[i] = 0;}}

//
// Check if a is zero, return 1, if not return 0
static int keys_zero(const u64 *a) {
  for (u08 i = 0; i < DI; ++i) {if (a[i]) {return 0;}}
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
  int i;
  for (i = DI - 1; i >= 0 && a[i] == 0; --i) {}
  return (i + 1);
}

//
// Set a from b
static void keys_set(u64 *a, const u64 *b) {
  for (u08 i = 0; i < DI; ++i) {a[i] = b[i];}
}

//
// Check number of bits needed for a
static ui keys_bits(u64 *a) {
  ui i, nd = keys_count(a); u64 d;

  if (nd == 0) return 0;
  nd--; d = a[nd];
  for (i = 0; d; ++i) d >>= 1;
  return ((nd) * 64 + i);
}

//
// Compare a and b
static int keys_cmp(const u64 *a, const u64 *b) {
  for (int i = DI-1; i >= 0; --i) {
    if (a[i] > b[i]) {return 1;}
    else if (a[i] < b[i]) {return -1;}
  }
  return 0;
}

//
// Left shift
static u64 keys_ls(u64 *a, const u64 *b, const ui c) {
  u64 ovr = 0;

  for (u08 i = 0; i < DI; ++i) {
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
  while (a-- > e) {u64 t = *a; *a = (t >> 1) | ovr; ovr = t << 63;}
}

//
// Adds b and c
static u64 keys_add(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0;

  for (u08 i = 0; i < DI; ++i) {
    u64 s = b[i] + c[i] + ovr;
    if (s != b[i]) {ovr = (s < b[i]);} a[i] = s;
  }
  return ovr;
}

//
// Sub b and c
static u64 keys_sub(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0;

  for (u08 i = 0; i < DI; ++i) {
    u64 d = b[i] - c[i] - ovr;
    if (d != b[i]) {ovr = (d > b[i]);} a[i] = d;
  }
  return ovr;
}

//
//
static void akrr(u64 **a, u64 k, u128 *r, u64 *r2) {
  (*a)[k] = (u64)(*r); (*r) = ((*r) >> 64) | (((u128)(*r2)) << 64); (*r2) = 0;
}

//
// Multiply
static void keys_mul(u64 *a, const u64 *b, const u64 *c) {
  u128 r = 0; u64 r2 = 0, di22 = DI * 2 - 1;

  for (u08 k = 0; k < di22; ++k) {
    ui min = (k < DI ? 0 : (k + 1) - DI);
    for (u08 j = min; j <= k && j < DI; ++j) {
      u128 p = (u128)b[j] * c[k - j]; // product
      r += p; r2 += (r < p);
    }
    akrr(&a, k, &r, &r2);
  }
  a[di22] = (u64)r;
}

//
// Square
static void keys_sqr(u64 *a, const u64 *b) {
  u128 r = 0; u64 r2 = 0, di22 = DI * 2 - 1;

  for (u08 k = 0; k < di22; ++k) {
    ui min = (k < DI ? 0 : (k + 1) - DI);
    for (u08 j = min; j <= k && j <= k - j; ++j) {
      u128 p = (u128)b[j] * b[k - j]; // product
      if (j < k - j) {r2 += p >> 127; p *= 2;}
      r += p; r2 += (r < p);
    }
    akrr(&a, k, &r, &r2);
  }
  a[di22] = (u64)r;
}

//
//
static void keys_o_mul(u64 *a, const u64 *b) {
  u64 t[DI], ovr;

  keys_set(a, b);
  ovr = keys_ls(t, b, 32);
  a[DI + 1] = ovr + keys_add(a + 1, a + 1, t);
  a[DI + 2] = keys_add(a + 2, a + 2, b);
  ovr += keys_sub(a, a, t);
  u64 d = a[DI] - ovr;
  if (d > a[DI]) {
    for (u08 i = 1+DI; ; ++i) {--a[i]; if (a[i] != (u64) - 1) {break;}}
  }
  a[DI] = d;
}

// Modulo functions

//
// Modulo add
static void keys_m_add(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  u64 ovr = keys_add(a, b, c);

  if (ovr || keys_cmp(a, m) >= 0) {keys_sub(a, a, m);}
}

//
// Modulo sub
static void keys_m_sub(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (keys_sub(a, b, c)) {keys_add(a, a, m);}
}

//
// Modulo mod
static void keys_m_mod(u64 *a, u64 *b) {
  u64 t[DI2];

  while (!keys_zero(b + DI)) {
    u64 ovr = 0;
    keys_clear(t); keys_clear(t + DI);
    keys_o_mul(t, b + DI);
    keys_clear(b + DI);
    for (u08 i = 0; i < DI + 3; ++i) {
      u64 s = b[i] + t[i] + ovr;
      if (s != b[i]) {ovr = (s < b[i]);}
      b[i] = s;
    }
  }
  while (keys_cmp(b, curve_p) > 0) {keys_sub(b, b, curve_p);}
  keys_set(a, b);
}

//
// Modulo multiply
static void keys_m_mul(u64 *a, const u64 *b, const u64 *c) {
  u64 p[DI2];

  keys_mul(p, b, c); keys_m_mod(a, p);
}

//
// Modulo square
static void keys_m_sqr(u64 *a, const u64 *b) {
  u64 p[DI2];

  keys_sqr(p, b); keys_m_mod(a, p);
}

//
// Modulo square root
static void keys_m_sqrt(u64 a[DI]) {
  u64 p1[DI] = {1}, r[DI] = {1};

  keys_add(p1, curve_p, p1);
  for (ui i = keys_bits(p1) - 1; i > 1; --i) {
    keys_m_sqr(r, r);
    if (keys_chk(p1, i)) {keys_m_mul(r, r, a);}
  }
  keys_set(a, r);
}

//
//
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

//
// Points is this zero?
static int keys_p_zero(pt *a) {return (keys_zero(a->x) && keys_zero(a->y));}

//
// Points double
static void keys_p_double(u64 *a, u64 *b, u64 *c) {
  u64 t4[DI], t5[DI];

  if (keys_zero(c)) {return;}
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

//
//
static void keys_p_decom(pt *a, const u64 b[KB + 1]) {
  u64 tr[DI] = {3};

  keys_set(a->x, b + 1);
  keys_m_sqr(a->y, a->x);
  keys_m_sub(a->y, a->y, tr, curve_p);
  keys_m_mul(a->y, a->y, a->x);
  keys_m_add(a->y, a->y, curve_b, curve_p);
  keys_m_sqrt(a->y);
  if ((a->y[0] & 0x01) != (b[0] & 0x01)) {keys_sub(a->y, curve_p, a->y);}
}

//
// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
static void keys_p_appz(u64 *a, u64 *b, const u64 *z) {
  u64 t[DI];

  keys_m_sqr(t, z);
  keys_m_mul(a, a, t);
  keys_m_mul(t, t, z);
  keys_m_mul(b, b, t);
}

//
// P = (x1, y1) => 2P, (x2, y2) => P'
static void keys_p_inidoub(u64 *a, u64 *b, u64 *c, u64 *d, u64 *p) {
  u64 z[DI];

  keys_set(c, a); keys_set(d, b);
  keys_clear(z); z[0] = 1;
  if (p) {keys_set(z, p);}
  keys_p_appz(a, b, z);
  keys_p_double(a, b, z);
  keys_p_appz(c, d, z);
}

//
// Points add
static void keys_p_add(u64 *a, u64 *b, u64 *c, u64 *d) {
  u64 t5[DI];

  keys_m_sub(t5, c, a, curve_p);
  keys_m_sqr(t5, t5);
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

//
// Points add
static void keys_p_addc(u64 *a, u64 *b, u64 *c, u64 *d) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  u64 t5[DI], t6[DI], t7[DI];

  keys_m_sub(t5, c, a, curve_p);
  keys_m_sqr(t5, t5);
  keys_m_mul(a, a, t5);
  keys_m_mul(c, c, t5);
  keys_m_add(t5, d, b, curve_p);
  keys_m_sub(d, d, b, curve_p);

  keys_m_sub(t6, c, a, curve_p);
  keys_m_mul(b, b, t6);
  keys_m_add(t6, a, c, curve_p);
  keys_m_sqr(c, d);
  keys_m_sub(c, c, t6, curve_p);

  keys_m_sub(t7, a, c, curve_p);
  keys_m_mul(d, d, t7);
  keys_m_sub(d, d, b, curve_p);

  keys_m_sqr(t7, t5);
  keys_m_sub(t7, t7, t6, curve_p);
  keys_m_sub(t6, t7, a, curve_p);
  keys_m_mul(t6, t6, t5);
  keys_m_sub(b, t6, b, curve_p);
  keys_set(a, t7);
}

//
// Modulo inversion
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

//
// Point multiplication
static void keys_p_mul(pt *r, pt *p, u64 *q, u64 *s) {
  u64 Rx[2][DI], Ry[2][DI], z[DI];
  int nb;

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
  keys_m_sub(z, Rx[1], Rx[0], curve_p);
  keys_m_mul(z, z, Ry[1-nb]);
  keys_m_mul(z, z, p->x);
  keys_m_inv(z, z, curve_p);
  keys_m_mul(z, z, p->y);
  keys_m_mul(z, z, Rx[1-nb]);

  // End 1/Z calculation
  keys_p_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  keys_p_appz(Rx[0], Ry[0], z);
  keys_set(r->x, Rx[0]);
  keys_set(r->y, Ry[0]);
}

// Public functions

//
// Random rotate
u64 prng_rotate(u64 x, u64 k) {return (x << k) | (x >> (32 - k));}

//
// Random next
u64 prng_next(void) {
  u64 e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);

  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

//
// Random init
void prng_init(u64 seed) {
  prng_ctx.a = 0xea7f00d1; prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (u64 i = 0; i < 31; ++i) {(void)prng_next();}
}

//
// Make public key
int keys_make_keys(u64 publ[KB + 1], u64 priv[KB]) {
  u64 private[DI], x = 1; // range [1, n-1]
  pt public;

  while(x) {
    if (keys_zero(private)) {continue;}
    if (keys_cmp(curve_n, private) != 1) {keys_sub(private, private, curve_n);}
    keys_p_mul(&public, &curve_g, private, NULL);
    x = keys_p_zero(&public);
  }
  keys_set(priv, private);
  keys_set(publ + 1, public.x);
  publ[0] = 2 + (public.y[0] & 0x01);
  return 1;
}

//
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

//
// Create signature
int keys_sign(const u64 priv[KB], const u64 hash[KB], u64 sign[KB2]) {
  u64 k[DI], tmp[DI], s[DI], x = 1;
  pt p;

  while (x) {
    if (keys_zero(k)) {continue;}
    if (keys_cmp(curve_n, k) != 1) {keys_sub(k, k, curve_n);}
    keys_p_mul(&p, &curve_g, k, NULL);
    if (keys_cmp(curve_n, p.x) != 1) {keys_sub(p.x, p.x, curve_n);}
    x = keys_zero(p.x);
  }
  keys_set(tmp, priv);
  keys_m_mmul(s, p.x, tmp, curve_n);
  keys_set(tmp, hash);
  keys_m_add(s, tmp, s, curve_n);
  keys_m_inv(k, k, curve_n);
  keys_m_mmul(s, s, k, curve_n);
  keys_set(sign, p.x);
  keys_set(sign + KB, s);
  return 1;
}

//
// Verify signature
int keys_vrfy(const u64 publ[KB + 1], const u64 hash[KB], const u64 sign[KB2]) {
  u64 tx[DI], ty[DI], tz[DI], r[DI], s[DI], u1[DI], u2[DI], z[DI], rx[DI], ry[DI];
  pt public, sum;

  keys_p_decom(&public, publ);
  keys_set(r, sign);
  keys_set(s, sign + KB);
  if (keys_zero(r) || keys_zero(s)) {return 0;}
  if (keys_cmp(curve_n, r) != 1 || keys_cmp(curve_n, s) != 1) {return 0;}
  keys_m_inv(z, s, curve_n);
  keys_set(u1, hash);
  keys_m_mmul(u1, u1, z, curve_n);
  keys_m_mmul(u2, r, z, curve_n);

  // Calculate sum = G + Q.
  keys_set(sum.x, public.x);
  keys_set(sum.y, public.y);
  keys_set(tx, curve_g.x);
  keys_set(ty, curve_g.y);
  keys_m_sub(z, sum.x, tx, curve_p);
  keys_p_add(tx, ty, sum.x, sum.y);
  keys_m_inv(z, z, curve_p);
  keys_p_appz(sum.x, sum.y, z);

  // Use Shamir's trick to calculate u1*G + u2*Q
  pt *points[4] = {NULL, &curve_g, &public, &sum};
  ui nb = (keys_bits(u1) > keys_bits(u2) ? keys_bits(u1) : keys_bits(u2));
  pt *point = points[(!!keys_chk(u1, nb - 1)) | ((!!keys_chk(u2, nb - 1)) << 1)];

  keys_set(rx, point->x);
  keys_set(ry, point->y);
  keys_clear(z);
  z[0] = 1;
  for (int i = nb - 2; i >= 0; --i) {
    keys_p_double(rx, ry, z);
    int index = (!!keys_chk(u1, i)) | ((!!keys_chk(u2, i)) << 1);
    pt *point = points[index];
    if (point) {
      keys_set(tx, point->x);
      keys_set(ty, point->y);
      keys_p_appz(tx, ty, z);
      keys_m_sub(tz, rx, tx, curve_p);
      keys_p_add(tx, ty, rx, ry);
      keys_m_mul(z, z, tz);
    }
  }
  keys_m_inv(z, z, curve_p);
  keys_p_appz(rx, ry, z);
  if (keys_cmp(curve_n, rx) != 1) {keys_sub(rx, rx, curve_n);}
  for (int i = 0 ; i < DI; i++) printf("%llu  %llu\n", rx[i], r[i]);

  return (keys_cmp(rx, r) == 0);
}
