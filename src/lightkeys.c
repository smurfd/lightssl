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
#include "lightkeys_defs.h"

//
// Imitate pythons %. -1 % 5 = 4, not -1
static int mod(const int n, const int m) {return ((n % m) + m) % m;}

//
// Clear a
static void keys_clear(u64 *a) {memset(a, 0, KD);}

//
// Check if a is zero, return 1, if not return 0
static int keys_zero(const u64 *a) {
  static const u64 zr[KD] = {0}; return !memcmp(a, zr, KD);
}

//
// Check if bit a or b is set, if so return diff from zero
static u64 keys_chk(const u64 *a, const u64 b) {
  return (a[b / 64] & ((u64)1 << (mod(b, 64))));
}

//
// Count 64bit in a
static u64 keys_count(const u64 *a) {
  u64 i = KD - 1; while(i >= 0 && a[i] == 0) {--i;} return i + 1;
}

//
// Set a from b
static void keys_set(u64 *a, const u64 *b) {memcpy(a, b, KD);}

//
// Check number of bits needed for a
static u64 keys_bits(u64 *a) {
  u64 i, d, nd = keys_count(a);
  if (nd == 0) return 0;
  nd--; d = a[nd];
  for (i = 0; d; ++i) d >>= 1;
  return (nd * 64 + i);
}

//
// Compare a and b
static int keys_cmp(const u64 *a, const u64 *b) {
  int c = memcmp(a, b, KD);
  if (c < 0) return -1;
  if (c > 0) return 1;
  return 0;
}

//
// Left shift
static u64 keys_ls(u64 *a, const u64 *b, const u64 c) {
  u64 ovr = 0;
  for (int i = 0; i < KD; ++i) {
    u64 t = b[i]; a[i] = (t << c) | ovr;
    ovr = t >> (64 - c);
  }
  return ovr;
}

//
// Right shift by 1
static u64 keys_rs1(u64 *a) {
  u64 *e = a, ovr = 0;
  a += KD;
  while (a-- > e) {
    u64 t = *a; *a = (t >> 1) | ovr;
    ovr = t << 63;
  }
}

//
// Adds b and c
static u64 keys_add(u64 *a, const u64 *b, const u64 *c) {
  u64 s, i, ovr = 0;
  for (i = 0; i < KD; ++i) {
    if ((s = b[i] + c[i] + ovr) != a[i]) {ovr = (s < b[i]);} a[i] = s;
  }
  return ovr;
}

//
// Sub b and c
static u64 keys_sub(u64 *a, const u64 *b, const u64 *c) {
  u64 ovr = 0, d;
  for (u64 i = 0; i < KD; ++i) {
    if ((d = b[i] - c[i] - ovr) != b[i]) {ovr = (d > b[i]);} a[i] = d;
  }
  return ovr;
}

static void akr(u64 *a, u64 k, u128 r, u64 r2) {
  a[k] = (u64)r; r = (r >> 64) | ((u128)r2 << 64); r2 = 0;
}

//
//
static void keys_mul(u64 *a, const u64 *b, const u64 *c) {
  u128 r = 0; u64 r2 = 0, min, kd2 = KD * 2 - 1;
  for (u64 k = 0; k < kd2; ++k) {
    min = (k < KD ? 0 : (k + 1) - KD);
    for (u64 j = min; j <= k & j < KD; ++j) {
      u128 p = (u128)b[j] * c[k - j]; // product
      r += p; r2 += (r < p);
    }
    akr(a, k, r, r2);
    //a[k] = (u64)r;
    //r = (r >> 64) | ((u128)r2 << 64);
    //r2 = 0;
  }
  a[kd2] = (u64)r;
}

static void keys_sqr(u64 *a, const u64 *b) {
  u128 r = 0; u64 min, r2 = 0, kd2 = KD * 2 - 1;
  for (u64 k = 0; k < kd2; ++k) {
    min = (k < KD ? 0 : (k + 1) - KD);
    for (u64 j = min; j <= k && j <= k - j; ++j) {
      u128 p = (u128)b[j] * b[k - j]; // product
      if (j < k - j) {r2 += p >> 127; p *= 2;}
      r += p; r2 += (r < p);
    }
    akr(a, k, r, r2);
    //a[k] = (u64)r;
    //r = (r >> 64) | ((u128)r2 << 64);
    //r2 = 0;
  }
  a[kd2] = (u64)r;
}

// Points functions
static int keys_p_zero(pt *a) {return keys_zero(a->x) && keys_zero(a->y);}

//
static void keys_o_mul(u64 *a, const u64 *b) {
  u64 t[KD], ovr, d;

  keys_set(a, b);
  ovr = keys_ls(t, b, 32);
  a[KD + 1] = ovr + keys_add(a + 1, a + 1, t);
  a[KD + 2] = keys_add(a + 2, a + 2, b);
  ovr += keys_sub(a, a, t);
  if ((d = a[KD] - ovr) > a[KD]) {
    for (u64 i = KD + 1;; ++i) {--a[i]; if (a[i] != (u64) - 1) {break;}}
  }
  a[KD] = d;
}

// Modulo functions
static void keys_m_add(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (keys_add(a, b, c) || keys_cmp(a, m) >= 0) {keys_sub(a, a, m);}
}

static void keys_m_sub(u64 *a, const u64 *b, const u64 *c, const u64 *m) {
  if (keys_sub(a, b, c)) {keys_add(a, a, m);}
}

static void keys_m_mod(u64 *a, u64 *b) {
  u64 t[KD2], s;
  while (!keys_zero(b + KD)) {
    u64 ovr = 0;
    keys_clear(t); keys_clear(t + KD);
    keys_o_mul(t, b + KD);
    keys_clear(b + KD);
    for (u64 i = 0; i < KD + 3; ++i) {
      if ((s = b[i] + t[i] + ovr) != b[i]) {ovr = (s < b[i]);}
      b[i] = s;
    }
  }
  while (keys_cmp(a, curve_p) > 0) {keys_sub(b, b, curve_p);}
  keys_set(a, b);
}

static void keys_m_mul(u64 *a, const u64 *b, const u64 *c) {
  u64 p[KD2];
  keys_mul(p, b, c);
  keys_m_mod(a, p);
}

static void keys_m_sqr(u64 *a, const u64 *b) {
  u64 p[KD2];
  keys_sqr(p, b);
  keys_m_mod(a, p);
}

static void keys_m_sqrt(u64 a[KD]) {
  u64 p1[KD] = {1}, r[KD] = {1};
  keys_add(p1, curve_p, p1);
  for (u64 i = keys_bits(p1) - 1; i > 1; --i) {
    keys_m_sqr(r, r);
    if (keys_chk(p1, i)) {keys_m_mul(r, r, a);}
  }
  keys_set(a, r);
}

static void keys_m_mmul(u64 *a, u64 *b, u64 *c, u64 *m) {
  u64 p[KD2], mm[KD2], ds, bs, pb, mb = keys_bits(m);
  keys_mul(p, b, c);
  if ((pb = keys_bits(p + KD))) {pb += KD * 64;}
  else {pb = keys_bits(p);};
  if (pb < mb) {keys_set(a, p); return;}

  keys_clear(mm); keys_clear(mm + KD);
  ds = (pb - mb) / 64; bs = mod(pb - mb, 64);
  if (bs) {mm[ds + KD] = keys_ls(mm + ds, m, bs);}
  else {keys_set(mm + ds, m);}

  keys_clear(a); a[0] = 1;
  while (pb > KD * 64 || keys_cmp(mm, m) >= 0) {
    int cmp = keys_cmp(KD + mm, KD + p);
    if (cmp < 0 || (cmp == 0 && keys_cmp(mm, p) <= 0)) {
      if (keys_sub(p, p, mm)) {keys_sub(KD + p, KD + p, a);}
      keys_sub(KD + p, KD + p, KD + mm);
    }
    u64 ovr = (mm[KD] & 0x01) << 63;
    keys_rs1(KD + mm); keys_rs1(mm);
    mm[KD - 1] |= ovr;
    --pb;
  }
  keys_set(a, p);
}
