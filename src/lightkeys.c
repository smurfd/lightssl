//                                                                                                                    //
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
#include <string.h>
#include <stdbool.h>
#include "lightkeys.h"
#include "lightdefs.h"
#include "lighttools.h"

//
// Clear a
static void clear(u64 *a) {
  memset(a, 0, DI * sizeof(u64));
}

//
// Count 64bit in a
static u64 count(const u64 *a) {
  for (int i = DI - 1; i >= 0; --i) if (a[i] != 0) return (i + 1);
  return 0;
}

//
// Set a from b
static void set(u64 *a, const u64 *b) {
  memcpy(a, b, DI * sizeof(u64));
}

//
// Check if a is zero, return 1, if not return 0
static int check_zero(const u64 *a) {
  if (a[0] == 0 && memcmp(a, a + 1, (DI - 1) * sizeof(a[0])) == 0) return 1;
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
  for (int i = DI - 1; i >= 0; --i) {
    if (a[i] > b[i]) return 1;
    else if (a[i] < b[i]) return -1;
  }
  return 0;
}

//
// Left shift
static u64 lshift(u64 *a, const u64 *b, const u64 c) {
  u64 ovr = 0;

  for (int i = 0; i < DI; ++i) {
    u64 t = b[i]; a[i] = (t << c) | ovr;
    ovr = t >> (64 - c);
  }
  return ovr;
}

//
// Right shift by 1
static void rshift1(u64 *a) {
  u64 *e = a, ovr = 0; a += DI;

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

  for (int i = 0; i < DI; ++i) {
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

  for (int i = 0; i < DI; ++i) {
    u64 d = b[i] - c[i] - ovr;
    if (d != b[i]) ovr = (d > b[i]);
    a[i] = d;
  }
  return ovr;
}

//
// Multiply
static void mul(u64 *a, const u64 *b, const u64 *c) {
  u128 r = 0; u64 r2 = 0, di22 = DI * 2 - 1;

  for (u64 k = 0; k < di22; ++k) {
    u64 min = (k < DI ? 0 : (k + 1) - DI);
    for (u64 j = min; j <= k && j < DI; ++j) {
      u128 p = (u128)b[j] * c[k - j]; // product
      r += p; r2 += (r < p);
    }
    a[k] = (u64)(r);
    r = (r >> 64) | (((u128)r2) << 64);
    r2 = 0;
  }
  a[di22] = (u64)r;
}

//
//
static void omega_mul(u64 *a, const u64 *b) {
  set(a, b);
  u64 t[DI], ovr = lshift(t, b, 32);
  a[DI + 1] = ovr + add(a + 1, a + 1, t);
  a[DI + 2] = add(a + 2, a + 2, b);
  ovr += sub(a, a, t);
  u64 d = a[DI] - ovr;
  if (d > a[DI]) {
    for (u64 i = 1 + DI; ; ++i) {
      if (--a[i] != (u64) - 1) break;
    }
  }
  a[DI] = d;
}

//
// Modulo add
static void mod_add(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (add(a, b, c) || compare(a, m) >= 0) sub(a, a, m);
}

//
// Modulo sub
static void mod_sub(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (sub(a, b, c)) add(a, a, m);
}

//
// Modulo mod
static void mod_mod(u64 *a, u64 *b) {
  while (!check_zero(b + DI)) {
    u64 ovr = 0, t[DI2];

    clear(t); clear(t + DI);
    omega_mul(t, b + DI);
    clear(b + DI);
    for (u64 i = 0; i < DI + 3; ++i) {
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
  u64 p[DI2];

  mul(p, b, c); mod_mod(a, p);
}

//
// Modulo square
static void mod_sqr(u64 *a, const u64 *b) {
  u64 p[DI2];

  mul(p, b, b); mod_mod(a, p);
}

//
// Modulo square root
static void mod_sqrt(u64 a[DI]) {
  u64 p1[DI] = {1}, r[DI] = {1};

  add(p1, curve_p, p1);
  for (u64 i = check_bits(p1) - 1; i > 1; --i) {
    mod_sqr(r, r);
    if (check_set(p1, i)) mod_mul(r, r, a);
  }
  set(a, r);
}

//
// Modulo multiply (b * c) % m
static void mod_mod_mul(u64 *a, u64 *b, u64 *c, u64 *m) {
  u64 ds, bs, pb, mb = check_bits(m), p[DI2], mm[DI2];

  mul(p, b, c);
  pb = check_bits(p + DI);
  if (pb) pb += DI * 64;
  else pb = check_bits(p);
  if (pb < mb) {
    set(a, p); return;
  }

  clear(mm); clear(mm + DI);
  ds = (pb - mb) / 64; bs = MOD(pb - mb, 64);
  if (bs) mm[ds + DI] = lshift(mm + ds, m, bs);
  else set(mm + ds, m);

  clear(a); a[0] = 1;
  while (pb > DI * 64 || compare(mm, m) >= 0) {
    int cmp = compare(DI + mm, DI + p);
    if (cmp < 0 || (cmp == 0 && compare(mm, p) <= 0)) {
      if (sub(p, p, mm)) sub(DI + p, DI + p, a);
      sub(DI + p, DI + p, DI + mm);
    }
    u64 ovr = (mm[DI] & 0x01) << 63;
    rshift1(DI + mm); rshift1(mm);
    mm[DI - 1] |= ovr;
    --pb;
  }
  set(a, p);
}

static void rs_sub_au(u64 *a, u64 *b, u64 *u, u64 *v, u64 *m, u64 car, bool sb) {
  if (sb) {
    sub(a, a, b); rshift1(a);
    if (compare(u, v) < 0) add(u, u, m);
    sub(u, u, v);
  } else rshift1(a);
  if (!EVEN(u)) car = add(u, u, m);
  rshift1(u);
  if (car) u[DI - 1] |= 0x8000000000000000;
}

//
// Modulo inversion
static void mod_invers(u64 *r, u64 *p, u64 *m) {
  u64 a[DI], b[DI], u[DI], v[DI], tmp[DI], car;
  int cmpResult;

  if(check_zero(p)) {clear(r); return;}
  set(a, p); set(b, m);
  clear(u); u[0] = 1; clear(v);
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
static int pt_check_zero(pt *a) {
  return (check_zero(a->x) && check_zero(a->y));
}

//
// Points double
static void pt_double(u64 *a, u64 *b, u64 *c) {
  u64 t4[DI], t5[DI];

  if (check_zero(c)) return;
  mod_sqr(t4, b); mod_mul(t5, a, t4); mod_sqr(t4, t4);
  mod_mul(b, b, c); mod_sqr(c, c);

  mod_add(a, a, c, curve_p); mod_add(c, c, c, curve_p);
  mod_sub(c, a, c, curve_p); mod_mul(a, a, c);

  mod_add(c, a, a, curve_p); mod_add(a, a, c, curve_p);
  if (check_set(a, 0)) {
    u64 ovr = add(a, a, curve_p);

    rshift1(a);
    a[DI - 1] |= ovr << 63;
  } else rshift1(a);
  mod_sqr(c, a); mod_sub(c, c, t5, curve_p); mod_sub(c, c, t5, curve_p);
  mod_sub(t5, t5, c, curve_p); mod_mul(a, a, t5); mod_sub(t4, a, t4, curve_p);
  set(a, c); set(c, b); set(b, t4);
}

//
// Points decompress
static void pt_decompress(pt *a, const uint8_t b[KB + 1]) {
  u64 tr[DI] = {3};

  bit_pack(a->x, b + 1);
  mod_sqr(a->y, a->x); mod_sub(a->y, a->y, tr, curve_p);
  mod_mul(a->y, a->y, a->x);
  mod_add(a->y, a->y, curve_b, curve_p); mod_sqrt(a->y);
  if ((a->y[0] & 0x01) != (b[0] & 0x01)) sub(a->y, curve_p, a->y);
}

//
// Points apply z
// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
static void pt_apply_z(u64 *a, u64 *b, u64 *z) {
  u64 t[DI];

  mod_sqr(t, z); mod_mul(a, a, t); mod_mul(t, t, z); mod_mul(b, b, t);
}

//
// Points init double
// P = (x1, y1) => 2P, (x2, y2) => P'
static void pt_init_double(u64 *a, u64 *b, u64 *c, u64 *d, const u64 *p) {
  u64 z[DI];

  set(c, a); set(d, b);
  clear(z); z[0] = 1;
  if (p) set(z, p);
  pt_apply_z(a, b, z); pt_double(a, b, z); pt_apply_z(c, d, z);
}

static void ssmm(u64 *t5, u64 *c, u64 *a, u64 *curve_p) {
  mod_sub(t5, c, a, curve_p); mod_sqr(t5, t5); mod_mul(a, a, t5);
  mod_mul(c, c, t5);
}

//
// Points add
static void pt_add(u64 *a, u64 *b, u64 *c, u64 *d) {
  u64 t5[DI];

  ssmm(t5, c, a, curve_p); mod_sub(d, d, b, curve_p); mod_sqr(t5, d);
  mod_sub(t5, t5, a, curve_p); mod_sub(t5, t5, c, curve_p);
  mod_sub(c, c, a, curve_p); mod_mul(b, b, c); mod_sub(c, a, t5, curve_p);
  mod_mul(d, d, c); mod_sub(d, d, b, curve_p); set(c, t5);
}

//
// Points add
// t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
static void pt_addc(u64 *a, u64 *b, u64 *c, u64 *d) {
  u64 t5[DI], t6[DI], t7[DI];

  ssmm(t5, c, a, curve_p); mod_add(t5, d, b, curve_p); mod_sub(d, d, b, curve_p);
  mod_sub(t6, c, a, curve_p); mod_mul(b, b, t6); mod_add(t6, a, c, curve_p);
  mod_sqr(c, d); mod_sub(c, c, t6, curve_p);

  mod_sub(t7, a, c, curve_p); mod_mul(d, d, t7); mod_sub(d, d, b, curve_p);

  mod_sqr(t7, t5); mod_sub(t7, t7, t6, curve_p); mod_sub(t6, t7, a, curve_p);
  mod_mul(t6, t6, t5); mod_sub(b, t6, b, curve_p); set(a, t7);
}

//
// Point multiplication
static void pt_mul(pt *r, pt *p, u64 *q, u64 *s) {
  u64 Rx[2][DI], Ry[2][DI], z[DI], nb;

  set(Rx[1], p->x); set(Ry[1], p->y);
  pt_init_double(Rx[1], Ry[1], Rx[0], Ry[0], s);
  for (int i = check_bits(q) - 2; i > 0; --i) {
    nb = !check_set(q, i);
    pt_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
    pt_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
  }
  nb = !check_set(q, 0);
  pt_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
  // Find final 1/Z value.
  mod_sub(z, Rx[1], Rx[0], curve_p);
  mod_mul(z, z, Ry[1 - nb]); mod_mul(z, z, p->x);
  mod_invers(z, z, curve_p); mod_mul(z, z, p->y); mod_mul(z, z, Rx[1 - nb]);

  pt_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]); pt_apply_z(Rx[0], Ry[0], z);
  set(r->x, Rx[0]); set(r->y, Ry[0]);
}

//
// Write cert to file
static u64 write_crt(FILE* ptr, uint8_t data[]) {
  int i = 4;

  fprintf(ptr, "-----BEGIN CERTIFICATE-----\n");
  fprintf(ptr, "MII");
  while (i < 1779) {fputc('y', ptr); if (i % 64 == 0) fputc('\n', ptr); i++;}
  fprintf(ptr, "==\n");
  fprintf(ptr, "-----END CERTIFICATE-----\n");
  return 1;
}

//
// Write key to file
static u64 write_key(FILE* ptr, uint8_t data[]) {
  char tmp[257] = {0};
  int i = 0, j = base64enc(data, 164, tmp);

  fprintf(ptr, "-----BEGIN EC PRIVATE KEY-----\n");
  while (i < j) {
    if (i != 0 && i % 64 == 0)
      fprintf(ptr, "\n");
    fprintf(ptr, "%c", tmp[i++]);
  }
  fprintf(ptr, "\n-----END EC PRIVATE KEY-----\n");
  return 1;
}

//
// Write cms to file
static u64 write_cms(FILE* ptr, uint8_t data[]) {
  fprintf(ptr, "%s\n", data);
  return 1;
}

//
// Write certificates/keys/cms
u64 keys_write(char *fn, uint8_t data[], int type) {
  FILE* ptr = fopen(fn, "w");
  u64 ret = 0;
  // type : 1 = certificate
  // type : 2 = private key
  // type : 3 = cms
  if (type == 1) ret = write_crt(ptr, data);
  if (type == 2) ret = write_key(ptr, data);
  if (type == 3) ret = write_cms(ptr, data);
  fclose(ptr);
  return ret;
}

//
// Make public key
int keys_make(uint8_t publ[KB + 1], uint8_t priv[KB], u64 private[DI]) {
  pt public;

  while(true) {
    if (compare(curve_n, private) != 1)
      sub(private, private, curve_n);
    pt_mul(&public, &curve_g, private, NULL);
    if (!pt_check_zero(&public)) break;
  }
  bit_unpack(priv, private); bit_unpack(publ + 1, public.x);
  publ[0] = 2 + (public.y[0] & 0x01);
  return 1;
}

//
// Create a secret from the public and private key
int keys_secr(const uint8_t pub[KB + 1], const uint8_t prv[KB], uint8_t scr[KB], u64 r[DI]) {
  pt public, product;
  u64 private[DI];

  pt_decompress(&public, pub);
  bit_pack(private, prv);
  pt_mul(&product, &public, private, r);
  bit_unpack(scr, product.x);
  return !pt_check_zero(&product);
}

//
// Create signature
int keys_sign(const uint8_t priv[KB], const uint8_t hash[KB], uint8_t sign[KB2], u64 k[DI]) {
  u64 tmp[DI], s[DI];
  pt p;

  do {
    if (check_zero(k)) continue;
    if (compare(curve_n, k) != 1) sub(k, k, curve_n);
    pt_mul(&p, &curve_g, k, NULL);
    if (compare(curve_n, p.x) != 1) sub(p.x, p.x, curve_n);
  } while (check_zero(p.x));
  bit_unpack(sign, p.x);
  bit_pack(tmp, priv);
  mod_mod_mul(s, p.x, tmp, curve_n);
  bit_pack(tmp, hash);
  mod_add(s, tmp, s, curve_n);
  mod_invers(k, k, curve_n); mod_mod_mul(s, s, k, curve_n);
  bit_unpack(sign + KB, s);
  return 1;
}

//
// Verify signature
int keys_vrfy(const uint8_t publ[KB + 1], const uint8_t hash[KB], const uint8_t sign[KB2]) {
  u64 u1[DI]={0}, u2[DI]={0}, tx[DI]={0}, ty[DI]={0}, tz[DI]={0}, rx[DI]={0}, ry[DI]={0}, rz[DI]={0};
  pt public, sum;


  pt_decompress(&public, publ);
  bit_pack(rx, sign); bit_pack(ry, sign + KB);
  if (check_zero(rx) || check_zero(ry)) return 0;
  if (compare(curve_n, rx) != 1 || compare(curve_n, ry) != 1) return 0;
  mod_invers(rz, ry, curve_n);
  bit_pack(u1, hash);
  mod_mod_mul(u1, u1, rz, curve_n); mod_mod_mul(u2, rx, rz, curve_n);

  // Calculate sum = G + Q.
  set(sum.x, public.x); set(sum.y, public.y);
  set(tx, curve_g.x); set(ty, curve_g.y);
  mod_sub(rz, sum.x, tx, curve_p); pt_add(tx, ty, sum.x, sum.y);
  mod_invers(rz, rz, curve_p); pt_apply_z(sum.x, sum.y, rz);
  // Use Shamir's trick to calculate u1*G + u2*Q
  pt *points[4] = {NULL, &curve_g, &public, &sum};
  uint32_t nb = (check_bits(u1) > check_bits(u2) ? check_bits(u1) : check_bits(u2));
  uint32_t n1 = (!!check_set(u1, nb - 1)) | ((!!check_set(u2, nb - 1)) << 1);
  set(rx, points[n1]->x); set(ry, points[n1]->y); clear(rz);
  rz[0] = 1;
  for (int i = nb - 2; i >= 0; --i) {
    pt_double(rx, ry, rz);
    uint32_t n2 = (!!check_set(u1, i)) | ((!!check_set(u2, i)) << 1);
    if (n2) {
      set(tx, points[n2]->x); set(ty, points[n2]->y);
      pt_apply_z(tx, ty, rz); mod_sub(tz, rx, tx, curve_p);
      pt_add(tx, ty, rx, ry); mod_mul(rz, rz, tz);
    }
  }
  mod_invers(rz, rz, curve_p); pt_apply_z(rx, ry, rz);
  if (compare(curve_n, rx) != 1)
    sub(rx, rx, curve_n);
  bit_pack(ry, sign);
  return (compare(rx, ry) == 0);
}
