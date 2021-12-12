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
#include "lightdefs.h"

void lightcrypt_init() {
  unsigned __int128 big1 = 123456788;
  __uint128_t big2 = 123456788;
  if(big1 == big2)
    printf("crypting stuff\n");

  struct tuple key;
  mpz_t za1, za21, za22, za3, k1, k2, k22;
  mpz_inits(za1, za21, za22, za3, k1, k2, k22, key.p1, key.p2, NULL);
  mpz_set_str(za1,"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
  mpz_set_str(za21, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
  mpz_set_str(za22, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
  mpz_set_str(za3, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
  mpz_set(curve.p, za1);
  mpz_set(curve.g.p1, za21);
  mpz_set(curve.g.p2, za22);
  mpz_set(curve.n, za3);
  strcpy(curve.name, "secp256k1");
  curve.a = 0;
  curve.b = 7;
  curve.h = 1;

  private_key(&k1);
  public_key(k1, &key);

  mpz_clear(za1);
  mpz_clear(za21);
  mpz_clear(za22);
  mpz_clear(za3);
  mpz_clear(k1);
  mpz_clear(k2);
  mpz_clear(k22);
}

void inverse_mod(mpz_t k, mpz_t pi, mpz_t *tmp) {
  mpz_t s, old_s, t, old_t, r, old_r, zero, one, gcd, x, y, tmp2, tmp3, neg, nk, quot;
  mpz_inits(s, t, r, old_s, old_t, old_r, zero, one, gcd, x, y, tmp2, tmp3, neg, nk, quot, NULL);

  mpz_set_ui(zero, 0);
  mpz_set_ui(one, 1);
  mpz_set_ui(neg, -1);

  if (mpz_cmp(k,zero) == 0) {
    printf("division by zero. not good\n");
    exit(0);
  }

  if (mpz_cmp(k, zero) < 0) {
    mpz_mul(nk, k, neg);
    inverse_mod(nk, pi, tmp);
    mpz_sub(tmp3, pi, *tmp);
    mpz_set(*tmp, tmp3);
    return;
  }

  mpz_set_ui(s, 0);
  mpz_set_ui(old_s, 1);
  mpz_set_ui(t, 1);
  mpz_set_ui(old_t, 0);
  mpz_set(r, pi);
  mpz_set(old_r, k);

  while (mpz_cmp(r, zero) != 0) {
    mpz_fdiv_q(quot, old_r, r);

    mpz_set(tmp2, r);
    mpz_mul(*tmp, quot, r);
    mpz_sub(r, old_r, *tmp);
    mpz_set(old_r, tmp2);

    mpz_set(tmp2, s);
    mpz_mul(*tmp, quot, s);
    mpz_sub(s, old_s, *tmp);
    mpz_set(old_s, tmp2);

    mpz_set(tmp2, t);
    mpz_mul(*tmp, quot, t);
    mpz_sub(t, old_t, *tmp);
    mpz_set(old_t, tmp2);
  }

  mpz_set(gcd, old_r);
  mpz_set(x, old_s);
  mpz_set(y, old_t);
  assert(mpz_cmp(gcd, one) == 0);
  mpz_mul(*tmp, k, x);
  mpz_mod(tmp2, *tmp, pi);
  assert(mpz_cmp(tmp2, one) == 0);
  mpz_mod(*tmp, x, pi);

  mpz_clear(s);
  mpz_clear(t);
  mpz_clear(r);
  mpz_clear(old_s);
  mpz_clear(old_t);
  mpz_clear(old_r);
  mpz_clear(zero);
  mpz_clear(one);
  mpz_clear(gcd);
  mpz_clear(x);
  mpz_clear(y);
  mpz_clear(tmp2);
  mpz_clear(tmp3);
  mpz_clear(neg);
  mpz_clear(nk);
}

bool is_on_curve(struct tuple point) {
  mpz_t x, y, tmpy, tmpx, tmpx2, tmpcx, tmpxy, tmpc, tmpcc, tmp1, tmp2, zero, ca, cb,null1;
  mpz_inits(x, y, tmpy, tmpx, tmpx2, tmpcx, tmpxy, tmpc, tmpcc, tmp1, tmp2, zero, ca, cb, null1, NULL);
  bool bret;

  if (point.empty == true) {
    return true;
  } 
  mpz_set(x, point.p1);
  mpz_set(y, point.p2);
  mpz_set_ui(zero, 0);
  mpz_mul(tmpy, y, y); // y*y
  mpz_mul(tmpx, x, x);
  mpz_mul(tmpx2, tmpx, x); // x*x*x
  mpz_set_ui(ca, curve.a);

  mpz_mul(tmpcx, ca, x);  // curve.a * x

  mpz_sub(tmpxy, tmpy, tmpx2); // y*y - x*x*x
  mpz_set_ui(cb, curve.b);
  mpz_sub(tmpc, tmpxy, tmpcx); // y*y - x*x*x - curve.a*x
  mpz_sub(tmpcc, tmpc, cb); // y*y - x*x*x - curve.a*x - curve.b
  mpz_mod(tmp2, tmpcc, curve.p);

  if (mpz_cmp(tmp2, zero) == 0) {
    bret = true;
  } else {
    bret = false;
  }
  mpz_clear(x);
  mpz_clear(y);
  mpz_clear(tmpx);
  mpz_clear(tmpy);
  mpz_clear(tmpx2);
  mpz_clear(tmpcx);
  mpz_clear(tmpxy);
  mpz_clear(tmpc);
  mpz_clear(tmp1);
  mpz_clear(tmp2);
  mpz_clear(zero);
  mpz_clear(ca);
  mpz_clear(cb);
  mpz_clear(null1);
  return bret;
}

void point_neg(struct tuple point, struct tuple *rest) {
  mpz_t x, y, negy, result, neg1, ymo;

  assert(is_on_curve(point));
  mpz_inits(x, y, negy, result, neg1, ymo, NULL);
  mpz_set(x, point.p1);
  mpz_set(y, point.p2);

  if (point.empty == true) {
    rest->empty = true;
    return;
  }
  mpz_set_ui(neg1, -1);
  mpz_mul(negy, y, neg1);
  mpz_mod(ymo, negy, curve.p);
  mpz_set(rest->p1, x);
  mpz_set(rest->p2, ymo);
  assert(is_on_curve(*rest));

  mpz_clear(x);
  mpz_clear(y);
  mpz_clear(negy);
  mpz_clear(neg1);
  mpz_clear(result);
  mpz_clear(ymo);
}

void point_add(struct tuple p1, struct tuple p2, struct tuple *r1) {
  mpz_t x1, y1, x2, y2, x3, y3, yn, m, tw, tr, tmptr, tmpx, tmpc, tmpca, tmpcp, tmp2y, neg, tt, zero;
  mpz_inits(x1, y1, x2, y2, x3, y3, yn, m, tw, tr, tmptr, tmpx, tmpc, tmpca, tmpcp, tmp2y, neg, tt, zero,NULL);
  assert(is_on_curve(p1)); // assert fails here lap 3
  assert(is_on_curve(p2));
  if (p1.empty == true) {
    r1 = &p2;
    return;
  }
  if (p2.empty == true) {
    r1 = &p1;
    return;
  }
  mpz_set(x1, p1.p1);
  mpz_set(y1, p1.p2);
  mpz_set(x2, p2.p1);
  mpz_set(y2, p2.p2);
  if ((mpz_cmp(x1, x2) == 0) && (mpz_cmp(y1, y2) != 0)) {
    r1->empty = true;
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
    inverse_mod(tmp2y, curve.p, &tt);
    mpz_mul(m, tmpc, tt);
  } else {
    mpz_sub(tmpx, x1, x2);
    mpz_sub(tmptr, y1, y2);
    inverse_mod(tmpx, curve.p, &tt);
    mpz_mul(m, tmptr, tt);
  }

  mpz_mul(tmptr, m, m);
  mpz_sub(tmpx, tmptr, x1);
  mpz_sub(x3, tmpx, x2);

  mpz_sub(tmpx, x3, x1);
  mpz_mul(tmp2y, m, tmpx);
  mpz_add(y3, y1, tmp2y);

  mpz_mod(tmpx, x3, curve.p);
  mpz_set_ui(neg, -1);
  mpz_neg(yn, y3);
  mpz_mod(tmptr, yn, curve.p);

  mpz_set(r1->p1, tmpx);
  mpz_set(r1->p2, tmptr);
  assert(is_on_curve(*r1));
  mpz_clear(x1);
  mpz_clear(x2);
  mpz_clear(x3);
  mpz_clear(y1);
  mpz_clear(y2);
  mpz_clear(y3);
  mpz_clear(yn);
  mpz_clear(m);
  mpz_clear(tw);
  mpz_clear(tr);
  mpz_clear(tmptr);
  mpz_clear(tmpc);
  mpz_clear(tmpca);
  mpz_clear(tmpcp);
  mpz_clear(tmp2y);
  mpz_clear(neg);
  mpz_clear(tt);
  mpz_clear(zero);
}

void scalar_mult(mpz_t kk, struct tuple point, struct tuple *tt) {
  struct tuple rest, adde;
  mpz_t x1, p1, p2, kk2, cn, result, result2, addend, addend2, zero, one, neg, nk;
  mpz_inits(x1, p1, p2, kk2, cn, result, result2, addend, addend2, zero, one, neg, nk, NULL);

  assert(is_on_curve(point));
  mpz_set_ui(zero, 0);
  mpz_set_ui(one, 1);
  mpz_set_ui(neg, -1);
  mpz_mod(cn, kk, curve.n);
  if (mpz_cmp(cn, zero) == 0 || point.empty == true) {
    tt->empty = true;
    return;
  }

  if (mpz_cmp(kk, zero) < 0) {
    point_neg(point, &point);
    mpz_mul(nk, kk, neg);
    scalar_mult(nk, point, tt);
    return;
  }
  adde = point;
  while (mpz_cmp(kk, zero) != 0) {
    mpz_and(kk2, kk, one);
    if (mpz_cmp(kk2, zero)) {
      point_add(rest, adde, &rest);
    }
    point_add(adde, adde, &adde);
    mpz_tdiv_q_2exp(kk, kk, 1);
  }
  assert(is_on_curve(rest));
  tt = &rest;

  mpz_clear(x1);
  mpz_clear(p1);
  mpz_clear(p2);
  mpz_clear(kk2);
  mpz_clear(cn);
  mpz_clear(result);
  mpz_clear(result2);
  mpz_clear(addend);
  mpz_clear(addend2);
  mpz_clear(zero);
  mpz_clear(one);
  mpz_clear(neg);
  mpz_clear(nk);
}

void private_key(mpz_t *key) {
  gmp_randstate_t ran;
  gmp_randinit_default(ran);
  mpz_urandomm(*key, ran, curve.n);
}

void public_key(mpz_t privkey, struct tuple *pubkey) {
  scalar_mult(privkey, curve.g, pubkey);
}
