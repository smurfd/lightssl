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
#include <gmp.h>
#include "lightcrypt.h"
#include "defs.h"

void lightcrypt_init() {
  unsigned __int128 big1 = 123456788;
  __uint128_t big2 = 123456788;
  if(big1 == big2)
    printf("crypting stuff\n");

  mpz_t za1;
  mpz_t za21;
  mpz_t za22;
  mpz_t za3;
  mpz_t k1, k2;
  mpz_inits(za1, za21, za22, za3, k1, k2, NULL);
  mpz_set_str(za1,"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefc2f", 16);
  mpz_set_str(za21, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
  mpz_set_str(za22, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
  mpz_set_str(za3, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
  struct rrr *r;

  mpz_set(curve.p, za1);
  mpz_set(curve.g1, za21);
  mpz_set(curve.g2, za22);
  mpz_set(curve.n, za3);
  strcpy(curve.name, "secp256k1");
  curve.a = 0;
  curve.b = 7;
  curve.h = 1;
  private_key(k1);
  r = (struct rrr*)malloc(96*sizeof(uint64_t));
  public_key(k1, k2);
}

void inverse_mod(mpz_t k, mpz_t pi, mpz_t tmp) {
  mpz_t s, old_s, t, old_t, r, old_r, zero, one, gcd, x, y, tmp2, tmp3, neg, nk;
  mpz_inits(s, t, r, old_s, old_t, old_r, zero, one, gcd, x, y, tmp2, tmp3, neg, nk, NULL);

  mpz_set_str(zero, "0", 10);
  mpz_set_str(one, "1", 10);
  mpz_set_str(s, "0", 10);
  mpz_set_str(old_s, "1", 10);
  mpz_set_str(t, "1", 10);
  mpz_set_str(old_t, "0", 10);
  mpz_set(r, pi);
  mpz_set(old_r, k);
  mpz_set_ui(neg, -1);

  if (mpz_cmp(k,zero) == 0) {
    mpz_set(tmp, zero);
    return;
  }

  if (mpz_cmp(k, zero) < 0) {
    mpz_mul(nk, k, neg);
    inverse_mod(nk, pi, tmp);
    mpz_sub(tmp3, pi, tmp);
    mpz_set(tmp, tmp3);
    return;
  }

  while (mpz_cmp(r, zero) != 0) {
    mpz_t quot;
    mpz_inits(quot, NULL);

    mpz_tdiv_q(quot, old_r, r);
    mpz_set(old_r, r);
    mpz_mul(tmp, quot, r);
    mpz_sub(r, old_r, tmp);
    mpz_set(old_s, s);
    mpz_mul(tmp, quot, s);
    mpz_sub(s, old_s, tmp);
    mpz_set(old_t, t);
    mpz_mul(tmp, quot, t);
    mpz_sub(t, old_t, tmp);
  }
  mpz_set(gcd, old_r);
  mpz_set(x, old_s);
  mpz_set(y, old_t);

  assert(mpz_cmp(gcd, one) == 0);
  mpz_mul(tmp, k, x);
  mpz_mod(tmp2, tmp, pi);
  assert(mpz_cmp(tmp2, one) == 0);
  mpz_mod(tmp, x, pi);
}

bool is_on_curve(mpz_t point, mpz_t point2) {
  // TODO: how to handle if tuple(or point?)
  // This works like shit...
  mpz_t x, y, tmpy, tmpx, tmpx2, tmpcx, tmpxy, tmpc, tmp1, tmp2, zero, ca, cb;
  if ((point == NULL) || (point == NULL && point2 == NULL)) {
    return true;
  }
  mpz_inits(x, y, tmpy, tmpx, tmpx2, tmpcx, tmpxy, tmpc, tmp1, tmp2, zero, ca, cb, NULL);
  mpz_set(x, point);
  mpz_set(y, point);
  mpz_set_str(zero, "0", 10);
  mpz_mul(tmpy, y, y);
  mpz_mul(tmpx, x, x);
  mpz_mul(tmpx2, tmpx, x);
  mpz_set_ui(ca, curve.a);
  mpz_mul(tmpcx, ca, x);
  mpz_sub(tmpxy, tmpy, tmpx2);
  mpz_set_ui(cb, curve.b);
  mpz_sub(tmpc, tmpcx, cb);
  mpz_sub(tmp1, tmpxy, tmpc);
  mpz_mod(tmp2, tmp1, curve.p);
  gmp_printf("tmp= %Zd...\n", tmp2);
  if (!point2) {
    if (mpz_cmp(tmp2, zero) == 0) {
      return true;
    } else {
      return false;
    }
  } else {
    mpz_set(x, point2);
    mpz_set(y, point2);
    mpz_set_str(zero, "0", 10);
    mpz_mul(tmpy, y, y);
    mpz_mul(tmpx, x, x);
    mpz_mul(tmpx2, tmpx, x);
    mpz_set_ui(ca, curve.a);
    mpz_mul(tmpcx, ca, x);
    mpz_sub(tmpxy, tmpy, tmpx2);
    mpz_set_ui(cb, curve.b);
    mpz_sub(tmpc, tmpcx, cb);
    mpz_sub(tmp1, tmpxy, tmpc);
    mpz_mod(tmp2, tmp1, curve.p);
    gmp_printf("tmp2= %Zd...\n", tmp2);
    if (mpz_cmp(tmp2, zero) == 0) {
      return true;
    } else {
      return false;
    }
  }
}

void point_neg(mpz_t point, mpz_t pr1, mpz_t pr2) {
  mpz_t x, y, negy, result, neg1, ymo;
  struct rrr res1;
  assert(is_on_curve(point, NULL));
  mpz_inits(x, y, negy, result, neg1, ymo, NULL);
  mpz_set(x, point);
  mpz_set(y, point);
  if (point == NULL) {
    res1.uniontype = 1;
    mpz_set(res1.u.p, NULL);
    mpz_set(pr1, NULL);
    mpz_set(pr2, NULL);
    return;
  }
  mpz_set_str(neg1, "-1", 10);
  mpz_mul(negy, y, neg1);
  mpz_mod(ymo, negy, curve.p);

  assert(is_on_curve(x, ymo));
  mpz_set(pr1, x);
  mpz_set(pr2, ymo);
}

void point_add(mpz_t point1, mpz_t point2, struct rrr *ret) {
  mpz_t x1, y1, x2, y2, x3, y3, yn, m, tw, tr, tmptr, tmpx, tmpc, tmpca, tmpcp, tmp2y, neg, tt;
  struct r res;
  struct rrr res1;
  gmp_printf("p1= %Zd...\n", point1);
  gmp_printf("p2= %Zd...\n", point2);
  assert(is_on_curve(point1, NULL));
  assert(is_on_curve(point2, NULL));
  mpz_inits(x1, y1, x2, y2, x3, y3, yn, m, tw, tr, tmptr, tmpx, tmpc, tmpca, tmpcp, neg, tt, NULL);

  if (point1 == NULL) {
    ret->uniontype = 1;
    mpz_set(ret->u.p, point2);
    return;
  }
  if (point2 == NULL) {
    ret->uniontype = 1;
    mpz_set(ret->u.p, point1);
    return;
  }
  mpz_set(x1, point1);
  mpz_set(y1, point1);
  mpz_set(x2, point2);
  mpz_set(x2, point2);
  if ((mpz_cmp(x1, x2) == 0) && (mpz_cmp(y1, y2) != 0)) {
    mpz_set(ret->u.p, NULL);
    return;
  }

  if (mpz_cmp(x1, x2) == 0) {
    mpz_set_ui(tw, 2);
    mpz_set_ui(tr, 3);
    mpz_mul(tmptr, tr, x1);
    mpz_mul(tmpx, tmptr, x1);
    mpz_set_ui(tmpca, curve.a);
    mpz_add(tmpc, tmpx, tmpca);
    mpz_mul(tmp2y, tw, y1);
    inverse_mod(tmp2y, curve.p, tt);
    mpz_mul(m, tmpc, tt);
  } else {
    mpz_sub(tmpx, x1, x2);
    mpz_sub(tmptr, y1, y2);
    inverse_mod(tmpx, curve.p, tt);
    mpz_mul(m, tmptr, tt);
  }

  mpz_sub(tmpx, x1, x2);
  mpz_mul(tmptr, m, m);
  mpz_sub(x3, tmptr, tmpx);

  mpz_sub(tmpx, x3, x1);
  mpz_add(tmptr, y1, m);
  mpz_mul(y3, tmptr, tmpx);

  mpz_mod(tmpx, x3, curve.p);
  mpz_set_ui(neg, -1);
  mpz_mul(yn, y3, neg);
  mpz_mod(tmptr, yn, curve.p);

  assert(is_on_curve(tmpx, tmptr));

  ret->uniontype = 2;
  mpz_set(ret->u.r3.r1, tmpx);
  mpz_set(ret->u.r3.r2, tmptr);
}

void scalar_mult(mpz_t kk, mpz_t point, mpz_t point2, mpz_t tt) {
  struct r res;
  struct r add;
  struct r p;
  struct rrr *pp2;
  struct rrr add1;
  struct rrr *add2;
  mpz_t x1, p1, p2, kk2, cn, result, addend, zero, one, neg, nk;
  mpz_inits(x1, p1, p2, kk2, cn, result, addend, zero, one, neg, nk, NULL);
  //assert(is_on_curve(point, point2));

  mpz_set_ui(zero, 0);
  mpz_set_ui(one, 1);
  mpz_set_ui(neg, -1);
  mpz_mod(cn, kk, curve.n);
  if ((mpz_cmp(cn, zero) == 0) || (point == NULL && point2 == NULL)) {
    mpz_set(tt, NULL);
    return;
  }

  if (mpz_cmp(kk, zero) < 0) {
    point_neg(point, p1, p2);
    mpz_mul(nk, kk, neg);
    scalar_mult(nk, p1, p2, tt);
    return;
  }
  pp2 = (struct rrr*) malloc(sizeof(struct rrr));
  mpz_set(addend, point);
  printf("--\n");
  while (kk) {
    printf("-\n");
    mpz_and(kk2, kk, one);
    printf("-\n");
    gmp_printf("kk2= %Zd...\n", kk2);
    if (mpz_cmp(kk2, zero)) {
      printf("-\n");
      point_add(result, addend, pp2);
      printf("-\n");
      mpz_set(result, pp2->u.p);
    }
    point_add(addend, addend, pp2);
    mpz_set(addend, pp2->u.p);
    mpz_tdiv_q_2exp(kk, kk, 1);
    //kk >>= 1;
  }
  printf("-\n");
  assert(is_on_curve(result, NULL));
  free(pp2);
  mpz_set(tt, result);
  //return result;
}

void private_key(mpz_t key) {
  gmp_randstate_t ran;
  gmp_randinit_default(ran);
  mpz_urandomm(key, ran, curve.n);
}

void public_key(mpz_t privkey, mpz_t pubkey) {
  scalar_mult(privkey, curve.g1, curve.g2, pubkey);
}
