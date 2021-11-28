//                                                                            //
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include "lightcrypt.h"
#include "defs.h"

extern const uint8_t a1[30];
extern const uint8_t a2_1[32];
extern const uint8_t a2_2[32];
extern const uint8_t a3[32];
 
void lightcrypt_init() {
  unsigned __int128 big1 = 123456788;
  __uint128_t big2 = 123456788;
  if(big1 == big2)
    printf("crypting stuff\n");

  struct rrr *r;
  uint8_t *k1;

  memcpy(curve.p, a1, sizeof(a1)*sizeof(uint8_t));
  memcpy(curve.g1, a2_1, sizeof(a2_1)*sizeof(uint8_t));
  memcpy(curve.g2, a2_2, sizeof(a2_2)*sizeof(uint8_t));
  memcpy(curve.n, a3, sizeof(a3)*sizeof(uint8_t));

  strcpy(curve.name, "secp256k1");
  curve.a = 0;
  curve.b = 7;
  curve.h = 1;

  for (int i=0;i<32; i++) {
    if (i % 4 == 0 && i != 0) {
      printf("\n");
    }
    printf("0x%x ", curve.g2[i]);
  }
  printf("\n--\n");
  k1 = (uint8_t*) malloc(30*sizeof(uint8_t));
  private_key(k1);
  for (int i=0; i<30; i++) {
    if (i % 4 == 0 && i != 0) {
      printf("\n");
    }
    printf("%d ", k1[i]);
  }
  printf("\n--\n");
  r = (struct rrr*)malloc(sizeof(struct rrr));
  //public_key(k1, r); // FIXME: fails tests
  is_on_curve((uint64_t*)a1);
  free(k1);
}

uint64_t inverse_mod(uint64_t k, uint64_t p) {
  if (k == 0) {
    return 0;
  }

  if (k < 0) {
    return p - inverse_mod(-k, p);
  }

  uint64_t s = 0;
  uint64_t old_s = 1;
  uint64_t t = 1;
  uint64_t old_t = 0;
  uint64_t r = p;
  uint64_t old_r = k;

  while (r != 0) {
    uint64_t quot = old_r / r;
    old_r = r;
    r = old_r - quot * r;
    old_s = s;
    s = old_s - quot * s;
    old_t = t;
    t = old_t - quot * t;
  }

  uint64_t gcd = old_r;
  uint64_t x = old_s;
  uint64_t y = old_t;

  assert(gcd == 1);
  assert((k*x) % p == 1);
  return x % p;
}

bool is_on_curve(uint64_t* point) {
  if (point == NULL) {
    return true;
  }
  uint64_t x[30];
  uint64_t y[30];
  uint64_t tmp[30];
  bool res = false;

  memcpy(x, point, sizeof(point)*sizeof(uint64_t));
  memcpy(y, point, sizeof(point)*sizeof(uint64_t));

  for (uint64_t i=0; i<sizeof(curve.p); i++) {
    tmp[i] = ((y[i]*y[i]) - (x[i]*x[i]*x[i]) - (curve.a * x[i]) - curve.b) % curve.p[i];
    if ((tmp[i] == 0) && (res == false)) {
      res = true;
    }
  }

  return res;
}

struct rrr point_neg(uint64_t *point) {
  uint64_t *x = point;
  uint64_t *y = point;
  struct r res;
  struct rrr res1;
  assert(is_on_curve(point));

  if (point == NULL) {
    res1.uniontype = 1;
    res1.u.p = NULL;
    return res1;
  }

  for (int i=0; i<sizeof(curve.p); i++) {
    res.r1[i] = x[i];
    res.r2[i] = -y[i] % curve.p[i];
  }
  assert(is_on_curve(res.r1));
  assert(is_on_curve(res.r2));
  res1.uniontype = 2;
  memcpy(res1.u.r3.r1, res.r1, sizeof(struct r)*sizeof(uint64_t));
  memcpy(res1.u.r3.r2, res.r2, sizeof(struct r)*sizeof(uint64_t));
  return res1;
}

void point_add(uint64_t *point1, uint64_t *point2, struct rrr *ret) {
  uint64_t x1[30];
  uint64_t y1[30];
  uint64_t x2[30];
  uint64_t y2[30];
  uint64_t x3[30];
  uint64_t y3[30];
  uint64_t m[30];
  struct r res;
  struct rrr res1;
  assert(is_on_curve(point1));
  assert(is_on_curve(point2));

  if (point1 == NULL) {
    ret->uniontype = 1;
    memcpy(ret->u.p, point2, sizeof(point2)*sizeof(uint64_t));
    return;
  }
  if (point2 == NULL) {
    ret->uniontype = 1;
    memcpy(ret->u.p, point1, sizeof(point1)*sizeof(uint64_t));
    return;
  }

  memcpy(x1, point1, sizeof(point1)*sizeof(uint64_t));
  memcpy(y1, point1, sizeof(point1)*sizeof(uint64_t));
  memcpy(x2, point2, sizeof(point2)*sizeof(uint64_t));
  memcpy(y2, point2, sizeof(point2)*sizeof(uint64_t));

  for (int i=0; i<30;i++) {
    if (x1[i] == x2[i] && y1[i] != y2[i]) {
      ret->uniontype = 1;
      ret->u.p = NULL;
      return;
    }

    if (x1[i] == x2[i]) {
      m[i] = (3*x1[i]*x1[i] + curve.a) * inverse_mod(2*y1[i], curve.p[i]);
    } else {
      m[i] = (y1[i] - y2[i]) * inverse_mod((x1[i] - x2[i]), curve.p[i]);
    }
    x3[i] = m[i] * m[i] - x1[i] - x2[i];
    y3[i] = y1[i] + m[i] * (x3[i] - x1[i]);
    res.r1[i] = (x3[i] % curve.p[i]);
    res.r2[i] = (-y3[i] % curve.p[i]);
  }
  assert(is_on_curve(res.r1));
  assert(is_on_curve(res.r2));
  ret->uniontype = 2;
  memcpy(ret->u.r3.r1, res.r1, sizeof(struct r)*sizeof(uint64_t));
  memcpy(ret->u.r3.r2, res.r2, sizeof(struct r)*sizeof(uint64_t));
}

struct rrr *scalar_mult(uint64_t k, struct rrr *p1, struct rrr *ret) {
  struct r res;
  struct r add;
  struct r p;
  struct rrr p2;
  struct rrr add1;
  struct rrr *add2;
  if (p1->uniontype == 1)
    assert(is_on_curve(p1->u.p));

  if (k % (uint64_t)curve.n == 0 || (p1->uniontype == 1 && p1->u.p == NULL)) {
    ret->uniontype = 1;
    ret->u.p = NULL;
    return ret;
  }

  if (k < 0) {
    if (p1->u.p == NULL) {
      ret->uniontype = 1;
      ret->u.p = NULL;
      return ret;
    } else {
      p2 = point_neg(p1->u.p);
      ret = scalar_mult(-k, &p2, ret);
      return ret;
    }
  }
  memcpy(add.r1, p1->u.p, sizeof(p1->u.p)*sizeof(uint64_t));
  memcpy(add.r2, p1->u.p, sizeof(p1->u.p)*sizeof(uint64_t));

  add2 = (struct rrr*) malloc(sizeof(struct rrr));
  while (k) {
    if (k & 1) {
      point_add(res.r1, add.r1, ret);
      point_add(res.r2, add.r2, ret);
    }
    point_add(add2->u.r3.r1, add2->u.r3.r1, add2);
    point_add(add2->u.r3.r2, add2->u.r3.r2, add2);
    k >>= 1;
  }
  assert(is_on_curve(res.r1));
  assert(is_on_curve(res.r2));
  ret->uniontype = 2;
  memcpy(ret->u.r3.r1, res.r1, sizeof(struct r)*sizeof(uint64_t));
  memcpy(ret->u.r3.r2, res.r2, sizeof(struct r)*sizeof(uint64_t));
  free(add2);
  return ret;
}

void private_key(uint8_t *ret) {
  srand(time(0));
  for (int i=0; i<30; i++) {
    ret[i] = rand() % 100;
  }
}

void public_key(uint8_t *pk, struct rrr *ret) {
  struct rrr *r;
  struct rrr r2;

  r = (struct rrr*) malloc(sizeof(struct rrr));

  printf("--- %lu\n", sizeof(struct rrr));
  r->uniontype = 2;
  // FIXME: Segfaults here....
  memcpy(r->u.r3.r1, curve.g1, 30*sizeof(uint8_t));
  printf("--- %lu\n", sizeof(uint8_t));
  memcpy(r->u.r3.r2, curve.g2, 30*sizeof(uint8_t));
  printf("----\n");
  for (int i=0; i<30; i++) {
    scalar_mult(pk[i], r, ret);
  }
  free(r);
}
