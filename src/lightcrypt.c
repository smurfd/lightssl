//                                                                            //
#include "lightcrypt.h"
#include "lightdefs.h"
#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

//
// Initialize crypt
void lightcrypt_init() {
  bigint_t *priv1, *priv2, *publ11, *publ12, *publ21, *publ22;
  big_init_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_init_m(4, &publ11, &publ12, &publ21, &publ22);
  big_alloc_max_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_alloc_max_m(4, &publ11, &publ12, &publ21, &publ22);
  big_set_m(4, &publ11, &publ12, &publ21, &publ22);
  char *tmpstr = malloc(MAXSTR);

  curve_name = malloc(10);
  // 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  big_set("115792089237316195423570985008687907853269984665640564039"
          "457584007908834671663",
    &curve_p);
  // 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  big_set("550662630222773436695787188951685343262506034537775941755"
          "00187360389116729240",
    &curve_g1);
  // 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  big_set("326705100207588169780830851305070431844712733806592432759"
          "38904335757337482424",
    &curve_g2);
  // 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  big_set("115792089237316195423570985008687907852837564279074904382"
          "605163141518161494337",
    &curve_n);
  strcpy(curve_name, "secp256k1");
  curve_a = 0;
  curve_b = 7;
  curve_h = 1;

  lightcrypt_privkey(&priv1);
  usleep(10);
  lightcrypt_privkey(&priv2);

  lightcrypt_publkey(priv1, &publ11, &publ12);
  lightcrypt_publkey(priv2, &publ21, &publ22);

  big_free_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_free_m(4, &publ11, &publ12, &publ21, &publ22);
  big_final_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_final_m(4, &publ11, &publ12, &publ21, &publ22);
  free(tmpstr);
  free(curve_name);
}

void lightcrypt_point_add(bigint_t *point1, bigint_t *point2, bigint_t *point3,
  bigint_t *point4, bigint_t **ret1, bigint_t **ret2) {
  // assert on_curve point1, point2
  // assert on_curve point3, point4
  if (point1->null && point2->null) {
    big_copy(point3, ret1);
    big_copy(point4, ret2);
  } else if (point3->null && point4->null) {
    big_copy(point1, ret1);
    big_copy(point2, ret2);
  } else {
    bigint_t *x1, *x2, *y1, *y2, *m;

    big_init_m(5, &x1, &x2, &y1, &y2, &m);
    big_alloc_max_m(1, &m);
    big_alloc_len(&x1, point1->len);
    big_alloc_len(&y1, point2->len);
    big_alloc_len(&x2, point3->len);
    big_alloc_len(&y2, point4->len);

    big_copy(point1, &x1);
    big_copy(point2, &y1);
    big_copy(point3, &x2);
    big_copy(point4, &y2);
    printf("point add aftr cp1\n");
    if (big_cmp(x1, x2) && !big_cmp(y1, y2)) {
      printf("point add aftr if1\n");
      big_set_null(ret1);
      big_set_null(ret2);
    } else {
      printf("point add aftr els1\n");
      if (big_cmp(x1, x2)) {
        bigint_t *two, *three, *y1y1, *x1x1, *x13, *bca, *bcax, *imd1;
        char *ca = malloc(10);
        printf("point add aftr if2\n");

        sprintf(ca, "%d", curve_a);
        big_init_m(8, &bca, &bcax, &two, &three, &y1y1, &x1x1, &x13, &imd1);
        big_alloc_len(&bca, strlen(ca));
        big_alloc_len(&two, 1);
        big_alloc_len(&three, 1);
        big_alloc_max_m(5, &y1y1, &x1x1, &x13, &bcax, &imd1);
        big_set_m(5, &y1y1, &x1x1, &x13, &bcax, &imd1);
        big_set("2", &two);
        big_set("3", &three);
        big_set(ca, &bca);

        big_mul(y1, two, &y1y1);
        big_mul(x1, x1, &x1x1);
        big_mul(x1x1, three, &x13);
        big_add(x13, bca, &bcax);
        // lightcrypt_point_imd(y1y1, curve_p, &imd1);
        big_mul(bcax, imd1, &m);

        big_final_m(8, &bca, &bcax, &two, &three, &y1y1, &x1x1, &x13, &imd1);
        free(ca);
      } else {
        printf("point add aftr els2\n");
        bigint_t *y1y2, *x1x2, *imd1;

        big_init_m(3, &y1y2, &x1x2, &imd1);
        big_alloc_max_m(3, &y1y2, &x1x2, &imd1);
        big_set_m(3, &y1y2, &x1x2, &imd1);
        big_sub(y1, y2, &y1y2);
        big_sub(x1, x2, &x1x2);
        // lightcrypt_point_imd(x1x2, curve_p, &imd1);
        big_mul(y1y2, imd1, &m);

        big_final_m(3, &y1y2, &x1x2, &imd1);
      }
      printf("after ifs\n");
      bigint_t *x3, *y3, *mm, *x1x2, *y1m, *x3x1, *x3m, *r1, *r2;

      big_init_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_alloc_max_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_set_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      printf("after ifs set\n");

      big_mul(m, m, &mm);
      big_sub(x1, x2, &x1x2);
      big_sub(mm, x1x2, &x3);
      printf("after ifs mulsubsub\n");

      big_sub(x3, x1, &x3x1);
      big_mul(m, x3x1, &x3m);
      big_add(y1, x3m, &y3);
      printf("after ifs submuladd\n");

      if (y3->neg == true) {
        y3->neg = false;
      } else {
        y3->neg = true;
      }
      printf("after ifs bfr modd\n");
      big_mod(x3, curve_p, &r1);
      big_mod(y3, curve_p, &r2);
      printf("after ifs aftr mod\n");
      // big_copy_ref(r1, ret1);
      // big_copy_ref(r2, ret2);
      printf("after ifs aftr mod2\n");
      big_final_m(7, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m);
      big_final_m(7, &x1, &x2, &y1, &y2, &m, &r1, &r2);
    }
    // assert on_curve ret1, ret2
  }
}

void lightcrypt_point_neg(
  bigint_t *point1, bigint_t *point2, bigint_t **ret1, bigint_t **ret2) {
  // assert on_curve(point1, point2)
  if (point1->null && point2->null) {
    big_set_null(ret1);
    big_set_null(ret2);
  } else {
    bigint_t *x, *y;

    big_init_m(2, &x, &y);
    big_alloc_len(&x, point1->len);
    big_alloc_len(&y, point2->len);

    big_copy(point1, &x);
    big_copy(point2, &y);

    big_copy(x, ret1);
    y->neg = true;
    big_mod(y, curve_p, ret2);

    // assert on_curve(ret1, ret2)
    big_final_m(2, &x, &y);
  }
}

void lightcrypt_point_mul(bigint_t *key, bigint_t *point1, bigint_t *point2,
  bigint_t **ret1, bigint_t **ret2) {
  bigint_t *kcn, *po1, *po2, *two, *addend1, *addend2;

  // assert on_curve(point1, point2)
  big_init_m(4, &kcn, &two, &addend1, &addend2);
  big_alloc_len(&kcn, key->len);
  big_alloc_len(&two, 1);
  big_alloc_max_m(2, &addend1, &addend2);
  big_set_m(3, &kcn, &addend1, &addend2);
  big_set("2", &two);

  big_mod(key, curve_n, &kcn);
  printf("mul aftr mod\n");
  if (big_cmp_str("0", kcn) == 1 || (point1->null && point2->null)) {
    printf("mul null\n");
    big_set_null(ret1);
    big_set_null(ret2);
  } else if (key->neg == true) {
    printf("mul neg\n");
    big_init_m(2, &po1, &po2);
    big_alloc_len(&po1, point1->len);
    big_alloc_len(&po2, point2->len);
    big_set_m(2, &po1, &po2);
    key->neg = false;
    lightcrypt_point_neg(point1, point1, &po1, &po2);
    lightcrypt_point_mul(key, po1, po2, ret1, ret2);
    big_free_m(2, &po1, &po2);
    big_final_m(2, &po1, &po2);
  } else {
    printf("mul else\n");
    big_set_null(ret1);
    big_set_null(ret2);
    big_copy(point1, &addend1);
    big_copy(point2, &addend2);
    printf("mul else bfr while\n");
    while (big_cmp_str("0", key) == 0) {
      bigint_t *k, *r1, *r2, *a1, *a2;

      big_init_m(5, &k, &a1, &a2, &r1, &r2);
      big_alloc_max_m(5, &k, &a1, &a2, &r1, &r2);
      big_set_m(5, &k, &a1, &a2, &r1, &r2);
      big_alloc_len(&k, key->len);
      printf("mul else in while aftr alloc\n");
      if (big_bit_and_one(key)) {
        printf("mul else in while in if\n");
        lightcrypt_point_add(*ret1, *ret2, addend1, addend2, &r1, &r2);
        printf("mul else in while in if aftr add\n");
        big_copy(r1, ret1);
        big_copy(r2, ret2);
      }
      printf("mul else in while aftr if\n");
      lightcrypt_point_add(addend1, addend2, addend1, addend2, &a1, &a2);
      big_copy(a1, &addend1);
      big_copy(a2, &addend2);
      big_div(key, two, &k);
      printf("mul else in while aftr div\n");
      big_copy(k, &key);
      // big_free_m(1, &k);
      big_final_m(5, &k, &a1, &a2, &r1, &r2);
      // big_final_m(1, &k);
    }
    // assert on_curve(ret1, ret2)
  }
  big_free_m(3, &two, &addend1, &addend2);
  big_final_m(4, &kcn, &two, &addend1, &addend2);
}

void lightcrypt_publkey(bigint_t *privkey, bigint_t **pub1, bigint_t **pub2) {
  lightcrypt_point_mul(privkey, curve_g1, curve_g2, pub1, pub2);
}

void lightcrypt_getrandstr(int len, char *ret) {
  srand(time(0));
  char char1[] = "0123456789";
  for (int i = 0; i < len; i++) {
    ret[i] = char1[rand() % (sizeof char1 - 1)];
  }
}

//
// Randomize to a bigint
void lightcrypt_random(bigint_t **p) {
  char *str = malloc(80);

  lightcrypt_getrandstr(80, str);
  big_set(str, &(*p));
  big_end_str(str);
}

//
// Initialize private key
void lightcrypt_privkey(bigint_t **privkey) { lightcrypt_random(privkey); }

//////////////////////////////////////////////////////////////////////

/*
void lightcrypt_init_t(bigtup_t **p) {
  (*p) = malloc(sizeof(bigtup_t));
  (*p)->alloc_t = true;
  big_init_m(2, &(*p)->p1, &(*p)->p2);
  big_alloc_max_m(2, &(*p)->p1, &(*p)->p2);
  big_set_m(2, &(*p)->p1, &(*p)->p2);
}

void lightcrypt_end_t(bigtup_t **p) {
  big_end_m(2, &(*p)->p1, &(*p)->p2);
  if ((*p)->alloc_t) {
    free((*p));
  }
}

void lightcrypt_init_t_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    lightcrypt_init_t(va_arg(valist, bigtup_t **));
  }
  va_end(valist);
}

void lightcrypt_end_t_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    lightcrypt_end_t(va_arg(valist, bigtup_t **));
  }
  va_end(valist);
}

//
// Copy a tuple
void lightcrypt_copy_t(bigtup_t *a, bigtup_t **b) {
  big_copy_ref(a->p1, &(*b)->p1);
  big_copy_ref(a->p2, &(*b)->p2);
}

void lightcrypt_getrandstr(int len, char *ret) {
  srand(time(0));
  char char1[] = "0123456789";
  for (int i = 0; i < len; i++) {
    ret[i] = char1[rand() % (sizeof char1 - 1)];
  }
}

//
// Randomize to a bigint
void lightcrypt_random(bigint_t **p) {
  char *str = malloc(80);

  lightcrypt_getrandstr(80, str);
  big_set(str, &(*p));
  big_end_str(str);
}

//
// Initialize private key
void lightcrypt_privkey(bigint_t **privkey) {
  lightcrypt_random(privkey);
}

//
// Initialize public key
void lightcrypt_pubkey(struct curve *cur,
                       bigint_t *privkey,
                       bigtup_t **pubkey) {
  big_set("32873365337033794512477405735997107923198513824305262159693765843969"
          "498982399885",
          &privkey);
  lightcrypt_point_mul(cur, privkey, cur->g, pubkey);
}

//
// Multiplication of points
void lightcrypt_point_mul(struct curve *cur,
                          bigint_t *key,
                          bigtup_t *point,
                          bigtup_t **ret) {
  bigtup_t *addend = NULL, *ad = NULL, *r = NULL, *npoint = NULL;
  bigint_t *kcn, *k1, *k2, *two;
  char *cc = (char *)malloc(MAXSTR);

  big_init_m(4, &k1, &k2, &two, &kcn);
  big_alloc_max_m(3, &k1, &k2, &kcn);
  big_set_m(3, &k1, &k2, &kcn);
  lightcrypt_init_t_m(4, &r, &ad, &addend, &npoint);
  lightcrypt_copy_t(point, &addend);
  big_alloc_len(&two, 1);
  big_set("2", &two);
  //   assert(lightcrypt_oncurve(cur, point));
  big_mod(key, cur->n, &kcn);
  if ((*kcn).dig[0] == 0 || point == NULL) {
    ret = NULL;
  } else if (key->neg) {
    key->neg = !key->neg;
    lightcrypt_point_neg(cur, point, &npoint);
    lightcrypt_point_mul(cur, key, npoint, ret);
  } else {
    while (big_cmp_str("0", key) == 0) {
      if (big_bit_and_one(key)) {
        if (ret != NULL) {
          lightcrypt_copy_t(*ret, &r);
        }
        lightcrypt_point_add(cur, r, addend, ret);
      }
      lightcrypt_point_add(cur, addend, addend, &ad);
      big_div(key, two, &k2); //_internal ??
      big_copy_ref(k2, &key);
      big_get(k2, cc);
      printf("k2 = %s\n", cc);
      lightcrypt_copy_t(ad, &addend);
    }
    if (ret != NULL) {
      // assert(lightcrypt_oncurve(cur, *ret));
    }
  }

  big_free(&k1);
  big_free(&k2);
  big_free(&two);
  big_free(&kcn);

  big_final(&k1);
  big_final(&k2);
  big_final(&two);
  big_final(&kcn);
  // big_end_m(4, &k1, &k2, &two, &kcn);
  // lightcrypt_end_t_m(4, &r, &ad, &addend, &npoint);
}

//
// Add two points
void lightcrypt_point_add(struct curve *cur,
                          bigtup_t *point1,
                          bigtup_t *point2,
                          bigtup_t **ret) {
  bigint_t *x1, *x2, *x3, *y1, *y2, *y3, *m, *mm, *mmm;
  bigtup_t *result = NULL;
  bool bret = false;

  big_init_m(5, &x1, &x2, &y1, &y2, &m);
  big_alloc_max_m(4, &x1, &x2, &y1, &y2);
  big_set_m(4, &x1, &x2, &y1, &y2);
  lightcrypt_init_t_m(1, &result);
  // assert(lightcrypt_oncurve(cur, point1));
  // assert(lightcrypt_oncurve(cur, point2));
  if (big_cmp_str("0", point1->p1) && big_cmp_str("0", point1->p2)) {
    bret = true;
    lightcrypt_copy_t(point2, ret);
  } else if (big_cmp_str("0", point2->p1) && big_cmp_str("0", point2->p2)) {
    bret = true;
    lightcrypt_copy_t(point1, ret);
  }
  if (!bret) {
    big_copy_ref(point1->p1, &x1);
    big_copy_ref(point1->p2, &y1);
    big_copy_ref(point2->p1, &x2);
    big_copy_ref(point2->p2, &y2);

    if (big_cmp(x1, x2) && !big_cmp(y1, y2)) {
      bret = true;
      ret = NULL;
    }
    if (!bret) {
      if (big_cmp(x1, x2)) {
        bigint_t *y12, *three, *x1x1, *inv, *xca, *ca;
        char *c = malloc(10);

        big_init_m(6, &y12, &three, &x1x1, &inv, &ca, &xca);
        big_alloc_max_m(7, &y12, &three, &x1x1, &inv, &ca, &xca, &m);
        big_set_m(7, &y12, &three, &x1x1, &inv, &ca, &xca, &m);

        sprintf(c, "%d", cur->a);
        big_set(c, &ca);

        big_add(y1, y1, &y12);
        lightcrypt_point_imd(cur, &y12, cur->p, &inv);

        big_set("3", &three);
        big_mul(x1, x1, &x1x1);
        printf("1\n");
        big_mul(three, x1x1, &x1x1);
        printf("2\n");
        big_add(x1x1, ca, &xca);
        printf("3\n");
        big_mul(xca, inv, &m);
        printf("4\n");

        // big_free(&y12);
        big_free(&three);
        // big_free(&x1x1);
        // big_free(&inv);
        big_free(&ca);
        big_free(&xca);

        // big_final(&y12);
        big_final(&three);
        // big_final(&x1x1);
        // big_final(&inv);
        big_final(&ca);
        big_final(&xca);

        // big_end_m(6, &y12, &three, &x1x1, &inv, &ca, &xca);
        // big_end_str(c);
      } else {
        bigint_t *x1x2, *y1y2, *inv;
        char *cc = malloc(MAXSTR);

        big_init_m(4, &x1x2, &y1y2, &inv, &m);
        big_alloc_max_m(4, &x1x2, &y1y2, &inv, &m);
        big_set_m(4, &x1x2, &y1y2, &inv, &m);

        big_sub(x1, x2, &x1x2);
        lightcrypt_point_imd(cur, &x1x2, cur->p, &inv);
        big_sub(y1, y2, &y1y2);
        printf("5\n");
        big_get(y1y2, cc);
        printf("y1 = %s\n", cc);
        big_get(inv, cc);
        printf("inv = %s\n", cc);
        big_get(m, cc);
        printf("m = %s\n", cc);
        big_clear_zeros(&y1y2);
        big_clear_zeros(&inv);
        big_mul(inv, y1y2, &m);
        printf("6\n");
      }
      printf("IND\n");
      big_init_m(4, &x3, &y3, &mm, &mmm);
      big_alloc_max_m(4, &x3, &y3, &mm, &mmm);
      big_set_m(4, &x3, &y3, &mm, &mmm);

      big_mul(m, m, &mm);    // m * m
      big_sub(mm, x1, &mmm); // m * m - x1;
      big_sub(mmm, x2, &x3); // x3 = m * m - x1 - x2

      big_sub(x3, x1, &mm);  // (x3 - x1)
      big_mul(m, mm, &mmm);  // m * (x3 - x1)
      big_add(y1, mmm, &y3); // y3 = y1 + m * (x3 - x1)

      y3->neg = !y3->neg;
      big_mod(x3, cur->p, &result->p1);
      big_mod(y3, cur->p, &result->p2);
      // assert(lightcrypt_oncurve(cur, result));
      lightcrypt_copy_t(result, ret);
    }
  }
  // lightcrypt_end_t_m(1, &result);
}

//
// Negate the point
void lightcrypt_point_neg(struct curve *cur, bigtup_t *point, bigtup_t **ret) {
  // assert(lightcrypt_oncurve(cur, point));
  if (point == NULL) {
    ret = NULL;
  } else {
    bigint_t *x, *y, *ycp;

    big_init_m(3, &x, &y, &ycp);
    big_set_m(3, &x, &y, &ycp);
    big_copy_ref(point->p1, &x);
    big_copy_ref(point->p2, &y);
    big_copy_ref(x, &(*ret)->p1);
    (*y).neg = true;
    big_mod(y, cur->p, &ycp);
    big_copy_ref(ycp, &(*ret)->p2);

    // assert(lightcrypt_oncurve(cur, *ret));
  }
}

//
// Inverse modulo
void lightcrypt_point_imd(struct curve *cur,
                          bigint_t **key,
                          bigint_t *point,
                          bigint_t **ret) {
  bigint_t *rr;
  bool bret = false;
  char *cc = malloc(MAXSTR);

  big_init_m(1, &rr);
  big_alloc_max_m(1, &rr);
  big_set_m(1, &rr);
  if (big_cmp_str("0", *key)) {
    bret = true;
    printf("this should not happen, zero division\n");
  }

  if (!bret) {
    if ((*key)->neg) {
      (*key)->neg = !(*key)->neg;
      lightcrypt_point_imd(cur, key, point, &rr);
      big_sub(point, rr, ret);
      bret = true;
    }
    if (!bret) {
      bigint_t *r, *s, *t, *old_r, *old_s, *old_t, *old_rt, *old_tt, *old_st,
        *qr, *qs, *qt, *quotient;

      big_init_m(13,
                 &r,
                 &s,
                 &t,
                 &old_r,
                 &old_s,
                 &old_t,
                 &old_rt,
                 &old_st,
                 &old_tt,
                 &qr,
                 &qs,
                 &qt,
                 &quotient);
      big_alloc_max_m(13,
                      &r,
                      &s,
                      &t,
                      &old_r,
                      &old_s,
                      &old_t,
                      &old_rt,
                      &old_st,
                      &old_tt,
                      &qr,
                      &qs,
                      &qt,
                      &quotient);
      big_set_m(
        9, &r, &old_r, &quotient, &old_rt, &old_st, &old_tt, &qr, &qs, &qt);

      big_set("0", &s);
      big_set("1", &old_s);

      big_set("1", &t);
      big_set("0", &old_t);

      big_copy_ref(point, &r);
      big_copy_ref(*key, &old_r);
      printf("----\n");
      while (!big_cmp_str("0", r)) {
        big_div(old_r, r, &quotient);

        big_copy(old_r, &old_rt);
        big_copy(old_s, &old_st);
        big_copy(old_t, &old_tt);

        big_copy(r, &old_r);
        big_copy(s, &old_s);
        big_copy(t, &old_t);

        big_mul(quotient, r, &qr);
        big_mul(quotient, s, &qs);
        big_mul(quotient, t, &qt);

        big_sub(old_rt, qr, &r);
        big_sub(old_st, qs, &s);
        big_sub(old_tt, qt, &t);
        //        big_sub_internal(old_rt, qr, &r);
        //        big_sub_internal(old_st, qs, &s);
        //        big_sub_internal(old_tt, qt, &t);
        big_clear_zeros(&r);

        big_get(r, cc);
        printf("r = %s : %d\n", cc, r->len);
        usleep(300000);
      }
      printf("-------------------------------\n");
      bigint_t *gcd, *x, *y;

      big_init_m(3, &gcd, &x, &y);
      big_alloc_max_m(3, &gcd, &x, &y);
      big_set_m(3, &gcd, &x, &y);

      big_copy_ref(old_r, &gcd);
      big_copy_ref(old_s, &x);
      big_copy_ref(old_t, &y);

      printf("-------------------------------\n");
      big_get(gcd, cc);
      printf("gcd = %s\n", cc);
      big_assert_str("1", &gcd);
      // assert (key*x) mod point = 1
      big_mod(x, point, ret);
      printf("-------------------------------\n");
      // big_end_m(3, &gcd, &x, &y);
      // big_end_m(13, &r, &s, &t, &old_r, &old_s, &old_t, &old_rt, &old_st,
      // &old_tt, &qr, &qs, &qt, &quotient);
    }
  }
}

//
// Check if point is on curve
bool lightcrypt_oncurve(struct curve *cur, bigtup_t *point) {
  bool ret = false;
  char *ca = NULL, *cb = NULL;
  bigint_t *x, *y, *res, *res1, *resxx, *resyy, *resxxx, *bca, *bcb;
  big_init_m(9, &x, &y, &res, &res1, &resxx, &resyy, &resxxx, &bca, &bcb);
  big_alloc_max_m(7, &x, &y, &res, &res1, &resxx, &resyy, &resxxx);
  big_set_m(7, &x, &y, &res, &res1, &resxx, &resyy, &resxxx);
  ca = malloc(MAXSTR);
  cb = malloc(MAXSTR);
  sprintf(ca, "%d", cur->a);
  sprintf(cb, "%d", cur->b);
  big_set(ca, &bca);
  big_set(cb, &bcb);

  if (point == NULL) {
    return true;
  }
  if ((*point).p1 == NULL || (*point).p2 == NULL) {
    return true;
  }
  //  if (strcmp("0", big_get((*point).p1)) == 0||strcmp("0",
  //      big_get((*point).p2)) == 0) {
  if (big_cmp_str("0", (*point).p1) || big_cmp_str("0", (*point).p2)) {
    return true;
  }
  big_copy_ref(point->p1, &x);
  big_copy_ref(point->p2, &y);
  big_set(ca, &bca);
  big_set(cb, &bcb);
  big_mul(x, x, &resxx);        // x*x
  big_mul(x, resxx, &resxxx);   // (x*x)*x
  big_mul(y, y, &resyy);        // y*y
  big_sub(resyy, resxxx, &res); // ((y*y)-((x*x)*x))
  big_mul(bca, x, &resxx);      // curve.a*x
  big_sub(res, resxx, &res1);   // ((y*y)-((x*x)*x))-(curve.a*x)
  big_sub(res1, bcb, &resyy);   // (((y*y)-((x*x)*x))-(curve.a*x)-curve.b)

  big_mod(resyy, cur->p, &res1); // % curve.p
  if ((*res1).len == 1 && (*res1).dig[0] == 0) {
    ret = true;
  }
  return ret;
}
*/
/*
//
// Initialize crypt
void lightcrypt_init() {
  bigint_t *priv, *priv2, *a;
  bigtup_t *publ = NULL, *publ2 = NULL, *scal1 = NULL, *scal2 = NULL;
  char *s = malloc(512);
  struct timespec remaining, request = {1, 0};
  struct curve *c = malloc(sizeof(struct curve));

  c->g = malloc(sizeof(bigtup_t));
  big_init_m(6, &(*c).p, &(*c).n, &(*c).g->p1, &(*c).g->p2, &priv, &a);
  big_set_m(5, &(*c).p, &(*c).n, &(*c).g->p1, &(*c).g->p2, &priv);

  // 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  big_set("115792089237316195423570985008687907853269984665640564039"\
      "457584007908834671663", &a);
  big_copy_ref(a, &(*c).p);

  // 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  big_set("550662630222773436695787188951685343262506034537775941755"\
      "00187360389116729240", &a);
  big_copy_ref(a, &(*c).g->p1);

  // 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  big_set("326705100207588169780830851305070431844712733806592432759"\
      "38904335757337482424", &a);
  big_copy_ref(a, &(*c).g->p2);

  // 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  big_set("115792089237316195423570985008687907852837564279074904382"\
      "605163141518161494337", &a);
  big_copy_ref(a, &(*c).n);

  strcpy((*c).name, "secp256k1");
  (*c).a = 0;
  (*c).b = 7;
  (*c).h = 1;

  lightcrypt_init_t(&publ);
  lightcrypt_init_t(&publ2);
  lightcrypt_init_t(&scal1);
  lightcrypt_init_t(&scal2);

  big_alloc(&(*publ).p1);
  big_alloc(&(*publ).p2);
  lightcrypt_privkey(&priv);
  lightcrypt_privkey(&priv2);

  lightcrypt_pubkey(&(*c), priv, &publ);
  nanosleep(&request, &remaining);
  lightcrypt_pubkey(&(*c), priv2, &publ2);

  printf("-----\n");
//  printf("pub : %s, %s\n", big_get((*publ).p1), big_get((*publ).p2));
//  printf("pub : %s, %s\n", big_get((*publ2).p1), big_get((*publ2).p2));
  printf("-----\n");

  lightcrypt_point_mul(&(*c), priv, publ2, &scal1);
  lightcrypt_point_mul(&(*c), priv2, publ, &scal2);

  printf("cmp1 %d\n", big_cmp(scal1->p1, scal2->p1));
  printf("cmp2 %d\n", big_cmp(scal1->p2, scal2->p2));

  lightcrypt_end_t(&publ);
  big_end_m(6, &(*c).p, &(*c).n, &(*c).g->p1, &(*c).g->p2, &priv, &a);
  if (c->g != NULL) {
    free(c->g);
  }
  if (c != NULL) {
    free(c);
  }
  if (s != NULL) {
    free(s);
  }
}

void lightcrypt_init_t(bigtup_t **p) {
  (*p) = malloc(sizeof(bigtup_t));
  (*p)->alloc_t = true;
  big_set_m(2, &(*p)->p1, &(*p)->p2);
}

void lightcrypt_end_t(bigtup_t **p) {
  if ((*p)->alloc_t) {
    free((*p));
  }
}

void lightcrypt_init_t_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    lightcrypt_init_t(va_arg(valist, bigtup_t**));
  }
  va_end(valist);
}

void lightcrypt_end_t_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    lightcrypt_end_t(va_arg(valist, bigtup_t**));
  }
  va_end(valist);
}

//
// Copy a tuple
void lightcrypt_copy_t(bigtup_t *a, bigtup_t **b) {
  big_copy_ref((*a).p1, &(*b)->p1);
  big_copy_ref((*a).p2, &(*b)->p2);
}

//
// Randomize to a bigint
void lightcrypt_rand(bigint_t **p) {
  char *s = malloc(MAXSTR);

  srand(time(0));
  sprintf(s, "%llu%llu%llu%llu", RAND64(), RAND64(), RAND64(),
      RAND64());
  big_init(p);
  big_set(s, &(*p));
  free(s);
}

//
// Randomize to a bigint tuple
void lightcrypt_rand_t(bigtup_t **p) {
  char *s = malloc(MAXSTR);

  srand(time(0));
  sprintf(s, "%llu%llu%llu%llu", RAND64(), RAND64(), RAND64(),
      RAND64());
  big_set(s, &(*p)->p1);
  sprintf(s, "%llu%llu%llu%llu", RAND64(), RAND64(), RAND64(),
      RAND64());
  big_set(s, &(*p)->p2);
  free(s);
}

char* lightcrypt_getrandstr(int len) {
  char *ret = calloc(1, len*sizeof(char));

  srand(time(0));
  char char1[] = "0123456789";
  for (int i=0; i<len; i++) {
    ret[i] = char1[rand() % (sizeof char1 - 1)];
  }
  return ret;
}

//
// Randomize to a bigint
void lightcrypt_random(bigint_t **p) {
  big_init(p);
  big_set(lightcrypt_getrandstr(80), &(*p));
}

//
// Initialize private key
void lightcrypt_privkey(bigint_t **privkey) {
  lightcrypt_random(privkey);
}

//
// Initialize public key
void lightcrypt_pubkey(struct curve *cur, bigint_t *privkey,
    bigtup_t **pubkey) {
  printf("PRIV: %s\n",
"32873365337033794512477405735997107923198513824305262159693765843969498982399885");//big_get(privkey));
//  printf("CUR-G : %s : %s\n", big_get(cur->g->p1), big_get(cur->g->p2));
  big_set("32873365337033794512477405735997107923198513824305262159693765843969498982399885",
&privkey); lightcrypt_point_mul(cur, privkey, cur->g, pubkey);
//  printf("PUBK: (%s, %s)\n", big_get((*pubkey)->p1), big_get((*pubkey)->p2));
  // FIXME: still an issue
  // should return(from python ecdhe.py):
  //
114228706046720397033883399099126209430656953859958883131997376409144460418386,
  //
81307239155600299831502865374878345877638639799606025680292741045527875388961
  //
  // returns:
  //55066263022277343669578718895168534326250603453777594175500187360389116729240,
  //32670510020758816978083085130507043184471273380659243275938904335757337482424
}

//
// Multiplication of points
void lightcrypt_point_mul(struct curve *cur, bigint_t *key,
    bigtup_t *point, bigtup_t **ret) {
  bigint_t *kcn, *k1, *k2, *t;
  bigtup_t *addend = NULL, *ad = NULL, *r = NULL, *npoint = NULL;

  lightcrypt_init_t_m(4, &r, &ad, &addend, &npoint);
  big_init_m(4, &k1, &k2, &t, &kcn);
  big_set_m(3, &k1, &k2, &kcn);
  big_set("2", &t);
  lightcrypt_copy_t(point, &addend);

  //assert(lightcrypt_oncurve(cur, point));
  big_mod(key, cur->n, &kcn);
  if ((*kcn).dig[0] == 0 || point == NULL) {
    ret = NULL;
  } else if (key->neg) {
    lightcrypt_point_neg(cur, point, &npoint);
    lightcrypt_point_mul(cur, key, npoint, ret);
  } else {
    while (big_cmp_str("0", key) == 0) {
      if (big_bit_and_one(key)) {
        if (ret != NULL) {
          lightcrypt_copy_t(*ret, &r);
        }
        lightcrypt_point_add(cur, r, addend, ret);
      }
      lightcrypt_point_add(cur, addend, addend, &ad);
      // FIXME: malloc: Region cookie corrupted between this print and next
      big_div(key, t, &k2);
      big_copy_ref(k2, &key);
      lightcrypt_copy_t(ad, &addend);
    }
    if (ret != NULL) {
      //assert(lightcrypt_oncurve(cur, *ret));
    }
  }
  lightcrypt_end_t(&addend);
}

//
// Add two points
void lightcrypt_point_add(struct curve *cur, bigtup_t *point1,
    bigtup_t *point2, bigtup_t **ret) {
  bigint_t *x1, *x2, *y1, *y2, *mmm, *yp2p1, *yp2p2, *y12, *x12, *x12p,
      *x12t, *mmm2, *mmm2x1, *mmm2x2, *mmm2x31, *mx31, *yx3, *yp2, *xx1,
      *xx3, *x3t, *xx3ca, *cab;
  bigtup_t *m = NULL, *y12p = NULL, *cpp = NULL, *yp2p = NULL,
      *x12pp = NULL, *x12ppp = NULL, *mm = NULL, *mm1 = NULL,
      *mm12 = NULL, *x3 = NULL, *y3 = NULL, *x31 = NULL, *y1m = NULL;
  char *ca = (char*) malloc(MAXSTR);
  bool bret = false;

  big_init_m(23, &x12t, &mmm2, &mmm2x1, &mmm2x2, &mmm2x31, &mx31,
        &yx3, &x1, &x2, &y1, &y2, &mmm, &yp2p1, &yp2p2, &y12, &x12,
        &x12p, &y12, &x3t, &yp2, &xx1, &xx3, &xx3ca);
  big_set_m(22, &x12t, &mmm2, &mmm2x1, &mmm2x2, &mmm2x31, &mx31,
        &yx3, &x1, &x2, &y1, &y2, &mmm, &yp2p1, &yp2p2, &y12, &x12,
        &x12p, &y12, &yp2, &xx1, &xx3, &xx3ca);
  lightcrypt_init_t_m(13, &mm, &mm1, &mm12, &x3, &y3, &x31, &y1m,
        &m, &y12p, &cpp, &yp2p, &x12pp, &x12ppp);

  sprintf(ca, "%d", cur->a);
  big_set("3", &x3t);
  big_set(ca, &cab);

  //assert(lightcrypt_oncurve(cur, point1));
  //assert(lightcrypt_oncurve(cur, point2));
  big_copy_ref(point1->p1, &x1);
  big_copy_ref(point1->p2, &y1);
  big_copy_ref(point2->p1, &x2);
  big_copy_ref(point2->p2, &y2);
//  if (strcmp(big_get(point1->p1), "0") == 0 && strcmp(big_get(
//        point1->p2), "0") == 0) {
  if (big_cmp_str("0", point1->p1) && big_cmp_str("0", point1->p2)) {
    if (ret == NULL) {
      lightcrypt_init_t_m(1, &ret);
    }
    lightcrypt_copy_t(point2, ret);
    bret = true;
  } else if (big_cmp_str("0", point2->p1) && big_cmp_str("0", point2->p2)) {
//  } else if (strcmp(big_get(point2->p1), "0") == 0 &&
//        strcmp(big_get(point2->p2), "0") == 0) {
    lightcrypt_copy_t(point1, ret);
    bret = true;
  } else if (big_cmp(x1, x2) && !big_cmp(y1, y2)) {
    bret = true;
  }

  if (bret == false) {
    if (x2 != NULL) {
      big_clear_zeros(&x2);
    }
    if (x1 != NULL) {
      big_clear_zeros(&x1);
    }
    if (big_cmp(x1, x2)) {
      big_add(y1, y1, &y12); // 2*y1
      lightcrypt_point_imd(cur, &y12, cur->p, &yp2p1);
      big_mul(x1, x1, &xx1); // x1*x1
      big_mul(xx1, x3t, &xx3); // 3*x1*x1
      big_add(xx3, cab, &xx3ca);  //
      big_mul(xx3ca, yp2p1, &mmm);
      //big_end_m(6, &y12, &x3, &yp2, &xx1, &xx3, &xx3ca);
    } else {
      big_sub(x1, x2, &x12);
      big_sub(y1, y2, &y12);
      lightcrypt_point_imd(cur, &y12, cur->p, &yp2p2);
      big_mul(y12, yp2p2, &mmm);
    }
    big_mul(mmm, mmm, &mmm2);
    big_sub(mmm2, x1, &mmm2x1);
    big_sub(mmm2x1, x2, &mmm2x2); // x3

    big_sub(mmm2x2, x1, &mmm2x31);
    big_mul(mmm, mmm2x31, &mx31);
    big_add(y1, mx31, &yx3); // y3

    if (yx3->neg) {
      yx3->neg = false;
    } else {
      yx3->neg = true;
    }
    lightcrypt_init_t_m(1, &ret);
    big_mod(mmm2x2, cur->p, &(*ret)->p1);
    big_mod(yx3, cur->p, &(*ret)->p2);
    //assert(lightcrypt_oncurve(cur, *ret));
  }
}

//
// Negate the point
void lightcrypt_point_neg(struct curve *cur, bigtup_t *point,
    bigtup_t **ret) {
  //assert(lightcrypt_oncurve(cur, point));
  if (point == NULL) {
    ret = NULL;
  } else {
    bigint_t *x, *y, *ycp;

    big_init_m(3, &x, &y, &ycp);
    big_set_m(3, &x, &y, &ycp);
    big_copy_ref(point->p1, &x);
    big_copy_ref(point->p2, &y);
    big_copy_ref(x, &(*ret)->p1);
    (*y).neg = true;
    big_mod(y, cur->p, &ycp);
    big_copy_ref(ycp, &(*ret)->p2);

    //assert(lightcrypt_oncurve(cur, *ret));
  }
}

//
// Inverse modulo
void lightcrypt_point_imd(struct curve *cur, bigint_t **key,
    bigint_t *point, bigint_t **ret) {
  bigint_t *r, *s, *t, *or, *os, *ot, *rr, *ss, *kss, *kssp, *q,
      *qr, *qs, *qt, *ort, *ott, *rt, *st, *tt, *ost;

  big_init_m(21, &q, &qr, &qs, &qt, &ort, &ost, &ott, &rt, &st, &r,
      &rr, &ss, &tt, &kss, &kssp, &r, &s, &t, &or, &os, &ot);
  big_set_m(21, &q, &qr, &qs, &qt, &ort, &ost, &ott, &rt, &st, &r,
      &rr, &ss, &tt, &kss, &kssp, &r, &s, &t, &or, &os, &ot);

  if ((*key)->dig[0] == 0) {
    printf("ZAROOOO DIVISION\n");
    // Should never happen, division by zero is bad
  }
  if ((*key)->neg == true) {
    (*key)->neg=false;
    lightcrypt_point_imd(cur, key, point, &r);
    big_sub(point, r, ret);
  } else {
    big_set("0", &s);
    big_set("1", &os);

    big_set("1", &t);
    big_set("0", &ot);

    big_copy_ref(point, &r);
    big_copy_ref(*key, &or);

    while (big_cmp_str("0", r) == 0) {
      big_div(or, r, &q);     // q = or // r
      big_copy_ref(or, &ort); // old_rr = old_r
      big_copy_ref(os, &ost);
      big_copy_ref(ot, &ott);

      big_copy_ref(r, &rt);   // rr = r
      big_copy_ref(s, &st);
      big_copy_ref(t, &tt);

      big_copy_ref(r, &or);   // old_r = r
      big_copy_ref(s, &os);
      big_copy_ref(t, &ot);

      big_mul(q, rt, &qr);    // qr = quotient * rr
      big_mul(q, st, &qs);
      big_mul(q, tt, &qt);
      big_sub(ort, qr, &r);   // r = old_rr - qr
      big_sub(ost, qs, &s);
      big_sub(ott, qt, &t);
      big_clear_zeros(&r);
    }
    big_copy_ref(or, &rr);
    big_copy_ref(os, &ss);
    big_copy_ref(ot, &tt);

    //assert(strcmp(big_get(rr), "1") == 0);

    big_mul(*key, ss, &kss);
    big_mod(kss, point, &kssp);
    //assert(strcmp(big_get(kssp), "1") == 0);

    big_mod(ss, point, ret);
  }
}

//
// Check if point is on curve
bool lightcrypt_oncurve(struct curve *cur, bigtup_t *point) {
  bool ret = false;
  char *ca = NULL, *cb = NULL;
  bigint_t *x, *y, *res, *res1, *resxx, *resyy, *resxxx, *bca, *bcb;
  big_init_m(9, &x, &y, &res, &res1, &resxx, &resyy, &resxxx, &bca,
      &bcb);
  big_set_m(7, &x, &y, &res, &res1, &resxx, &resyy, &resxxx);
  ca = malloc(MAXSTR);
  cb = malloc(MAXSTR);
  sprintf(ca, "%d", cur->a);
  sprintf(cb, "%d", cur->b);
  big_set(ca, &bca);
  big_set(cb, &bcb);

  if (point == NULL) {
    return true;
  }
  if ((*point).p1 == NULL||(*point).p2 == NULL) {
    return true;
  }
//  if (strcmp("0", big_get((*point).p1)) == 0||strcmp("0",
//      big_get((*point).p2)) == 0) {
  if (big_cmp_str("0", (*point).p1) || big_cmp_str("0", (*point).p2)) {
    return true;
  }
  big_copy_ref(point->p1, &x);
  big_copy_ref(point->p2, &y);
  big_set(ca, &bca);
  big_set(cb, &bcb);
  big_mul(x, x, &resxx);         // x*x
  big_mul(x, resxx, &resxxx);    // (x*x)*x
  big_mul(y, y, &resyy);         // y*y
  big_sub(resyy, resxxx, &res);  // ((y*y)-((x*x)*x))
  big_mul(bca, x, &resxx);       // curve.a*x
  big_sub(res, resxx, &res1);    // ((y*y)-((x*x)*x))-(curve.a*x)
  big_sub(res1, bcb, &resyy);    // (((y*y)-((x*x)*x))-(curve.a*x)-curve.b)

  big_mod(resyy, cur->p, &res1); // % curve.p
  if ((*res1).len == 1 && (*res1).dig[0] == 0) {
    ret = true;
  }
  return ret;
}
*/
