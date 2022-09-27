//                                                                            //
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <inttypes.h>
#include "lightdefs.h"
#include "lightcrypt.h"

//
// Initialize crypt
// p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
// g1= 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
// g2= 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
// n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
void lc_init() {
  big *priv1, *priv2, *publ11, *publ12, *publ21, *publ22;
  big_init_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_init_m(4, &publ11, &publ12, &publ21, &publ22);
  big_alloc_max_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_alloc_max_m(4, &publ11, &publ12, &publ21, &publ22);
  //big_set_m(6, &publ11, &publ12, &publ21, &publ22, &priv1, &priv2);
  char *tmpstr = malloc(MAXSTR);

  curve_name = malloc(10);
  big_set("11579208923731619542357098500868790785326998466564056403945758400790\
8834671663", &curve_p);
  big_set("55066263022277343669578718895168534326250603453777594175500187360389\
116729240", &curve_g1);
  big_set("32670510020758816978083085130507043184471273380659243275938904335757\
337482424", &curve_g2);
  big_set("11579208923731619542357098500868790785283756427907490438260516314151\
8161494337", &curve_n);
  strcpy(curve_name, "secp256k1");
  curve_a = 0;
  curve_b = 7;
  curve_h = 1;

  lc_privkey(&priv1);
  usleep(10);
  lc_privkey(&priv2);

  lc_publkey(priv1, &publ11, &publ12);
  lc_publkey(priv2, &publ21, &publ22);
  //big_end_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  //big_end_m(4, &publ11, &publ12, &publ21, &publ22);
  free(tmpstr);
  free(curve_name);
}

void lc_point_add(big *p1, big *p2, big *p3, big *p4, big **ret1, big **ret2) {
  assert(lc_on_curve(p1, p2));
  assert(lc_on_curve(p3, p4));

  if (p1->null && p2->null) {big_copy(p3, ret1); big_copy(p4, ret2);}
  else if (p3->null && p4->null) {big_copy(p1, ret1); big_copy(p2, ret2);}
  else {
    big *x1, *x2, *y1, *y2, *m;

    big_init_m(5, &x1, &x2, &y1, &y2, &m);
    big_alloc_max_m(1, &m);
    big_alloc_len(&x1, p1->len);
    big_alloc_len(&y1, p2->len);
    big_alloc_len(&x2, p3->len);
    big_alloc_len(&y2, p4->len);

    big_copy(p1, &x1);
    big_copy(p2, &y1);
    big_copy(p3, &x2);
    big_copy(p4, &y2);
    printf("point add aftr cp1\n");
    if (big_cmp(x1, x2) && !big_cmp(y1, y2)) {
      printf("point add aftr if1\n");
      big_set_null(ret1);
      big_set_null(ret2);
    } else {
      printf("point add aftr els1\n");
      if (big_cmp(x1, x2)) {
        big *two, *three, *y1y1, *x1x1, *x13, *bca, *bcax, *imd1;
        char *ca = malloc(10);
        printf("point add aftr if2\n");

        sprintf(ca, "%d", curve_a);
        big_init_m(8, &bca, &bcax, &two, &three, &y1y1, &x1x1, &x13, &imd1);
        big_alloc_len(&bca, strlen(ca));
        big_alloc_len(&two, 1);
        big_alloc_len(&three, 1);
        big_alloc_max_m(5, &y1y1, &x1x1, &x13, &bcax, &imd1);
        //big_set_m(5, &y1y1, &x1x1, &x13, &bcax, &imd1);
        big_set("2", &two);
        big_set("3", &three);
        big_set(ca, &bca);

        big_mul(y1, two, &y1y1);
        big_mul(x1, x1, &x1x1);
        big_mul(x1x1, three, &x13);
        big_add(x13, bca, &bcax);
        lc_inverse_mod(y1y1, curve_p, &imd1);
        big_mul(bcax, imd1, &m);

        //big_end_m(8, &bca, &bcax, &two, &three, &y1y1, &x1x1, &x13, &imd1);
        free(ca);
      } else {
        printf("point add aftr els2\n");
        big *y1y2, *x1x2, *imd1;

        big_init_m(3, &y1y2, &x1x2, &imd1);
        big_alloc_max_m(3, &y1y2, &x1x2, &imd1);
        //big_set_m(3, &y1y2, &x1x2, &imd1);
        big_sub(y1, y2, &y1y2);
        big_sub(x1, x2, &x1x2);
        lc_inverse_mod(x1x2, curve_p, &imd1);
        big_mul(y1y2, imd1, &m);

        //big_end_m(3, &y1y2, &x1x2, &imd1);
      }
      printf("after ifs\n");
      big *x3, *y3, *mm, *x1x2, *y1m, *x3x1, *x3m, *r1, *r2;
      big *tmp1, *tmp2;

      big_init_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_init_m(2, &tmp1, &tmp2);
      big_alloc_max_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_alloc_max_m(2, &tmp1, &tmp2);
      //big_set_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      //big_set_m(2, &tmp1, &tmp2);
      printf("after ifs set\n");

      big_mul(m, m, &mm);
      big_sub(x1, x2, &x1x2);
      big_sub(mm, x1x2, &x3);
      printf("after ifs mulsubsub\n");

      big_sub(x3, x1, &x3x1);
      big_mul(m, x3x1, &x3m);
      big_add(y1, x3m, &y3);
      printf("after ifs submuladd\n");

      if (y3->neg == true) {y3->neg = false;}
      else {y3->neg = true;}
      printf("after ifs bfr modd\n");
      // ret1 = x3 % curve_p
      big_div(x3, curve_p, &tmp1);
      big_mul(tmp1, curve_p, &tmp2);
      big_sub(x3, tmp2, ret1);
      big_clear_zeros(ret1);

      // ret2 = y3 % curve_p
      big_div(y3, curve_p, &tmp1);
      big_mul(tmp1, curve_p, &tmp2);
      big_sub(y3, tmp2, ret2);
      big_clear_zeros(ret2);
      //big_end_m(7, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m);
      //big_end_m(7, &x1, &x2, &y1, &y2, &m, &r1, &r2);
    }
    // assert on_curve ret1, ret2
  }
}

void lc_inverse_mod(big *key, big *p, big **ret) {
  if (big_cmp_str("0", key)) {
    printf("Div by zero, nah!\n");
    exit(0);
  } else if (key->neg) {
    big *r;
    big_init_m(1, &r);
    big_alloc_max_m(1, &r);
    //big_set_m(1, &r);
    key->neg = false;
    lc_inverse_mod(key, p, &r);
    big_sub(p, r, ret);
    //big_end_m(1, &r);
  } else {
    big *q, *r, *s, *t, *old_r, *old_s, *old_t, *r_tmp, *s_tmp, *t_tmp, *qt;
    big *gcd, *x, *y, *xt, *xp;
    big_init_m(9, &q, &r, &s, &t, &old_r, &old_s, &old_t, &r_tmp, &s_tmp);
    big_init_m(7, &t_tmp, &qt, &gcd, &x, &y, &xt, &xp);
    big_alloc_m(9, &q, &r, &s, &t, &old_r, &old_s, &old_t, &r_tmp, &s_tmp);
    big_alloc_m(7, &t_tmp, &qt, &gcd, &x, &y, &xt, &xp);
    //big_set_m(10, &q, &r, &old_r, &r_tmp, &s_tmp, &t_tmp, &qt, &gcd, &x, &y);
    //big_set_m(2, &xt, &xp);
    big_set("0", &s);
    big_set("1", &t);
    big_copy(p, &r);
    big_set("1", &old_s);
    big_set("0", &old_t);
    big_copy(key, &old_r);
    printf("inv mod bfr while\n");
    while (!big_cmp_str("0", r)) {
      big_div(old_r, r, &q);

      big_mul(q, r, &qt);
      big_sub(old_r, qt, &r_tmp);

      big_mul(q, s, &qt);
      big_sub(old_s, qt, &s_tmp);

      big_mul(q, t, &qt);
      big_sub(old_t, qt, &t_tmp);

      big_copy_ref(r, &old_r);
      big_copy_ref(s, &old_s);
      big_copy_ref(t, &old_t);

      big_copy_ref(r_tmp, &r);
      big_copy_ref(s_tmp, &s);
      big_copy_ref(t_tmp, &t);
      printf("while...\n");
    }
    printf("inv mod aft while\n");
    big_copy(old_r, &gcd);
    big_copy(old_s, &x);
    big_copy(old_t, &y);

    big_assert("1", &gcd);
    big_mul(key, x, &xt);
    big_mod(xt, p, &xp);
    big_assert("1", &xp);

    big_mod(x, p, ret);
    //big_end_m(9, &q, &r, &s, &t, &old_r, &old_s, &old_t, &r_tmp, &s_tmp);
    //big_end_m(7, &t_tmp, &qt, &gcd, &x, &y, &xt, &xp);
  }
}

bool lc_on_curve(big *p1, big *p2) {
  big *x, *y, *xx, *yy, *xxx, *cax, *yyx, *yyc, *yycc, *cccc, *ca, *cb;
  char *a = malloc(10), *b = malloc(10);
  bool ret;

  if (p1->null && p2->null) {return true;}
  big_init_m(12, &x, &y, &xx, &yy, &xxx, &cax, &yyx, &yyc, &yycc, &cccc, &ca, &cb);
  big_alloc_max_m(12, &x, &y, &xx, &yy, &xxx, &cax, &yyx, &yyc, &yycc, &cccc, &ca, &cb);
  //big_set_m(10, &x, &y, &xx, &yy, &xxx, &cax, &yyx, &yyc, &yycc, &cccc);

  sprintf(a, "%d", curve_a);
  sprintf(b, "%d", curve_b);
  printf("a=%s\n", a);
  printf("b=%s\n", b);

  big_set(a, &ca);
  big_set(b, &cb);
  big_copy(p1, &x);
  big_copy(p2, &y);

  big_mul(x, x, &xx);
  big_mul(y, y, &yy);
  big_mul(xx, x, &xxx);
  big_mul(ca, x, &cax);

  big_get(yy, a);
  printf("yy=%s\n", a);
  big_get(xxx, a);
  printf("xxx=%s\n", a);
  big_sub(yy, xxx, &yyx);
  big_get(yyx, a);
  printf("yyx=%s\n", a);

  //  big_sub(yyx, cax, &yyc);
  big_sub(yyx, cb, &yycc);
  big_get(yycc, a);
  printf("yycc=%s\n", a);

  big_mod(yycc, curve_p, &cccc);
  ret = big_cmp_str("0", cccc);
  big_get(cccc, a);
  printf("ret = %d : %s\n", ret, a);
  //free(b);
  //free(a);
  //big_end_m(10, &x, &y, &xx, &yy, &xxx, &cax, &yyx, &yyc, &yycc, &cccc);
  return ret;
}

void lc_point_neg(big *p1, big *p2, big **ret1, big **ret2) {
  // assert on_curve(p1, p2)
  if (p1->null && p2->null) {big_set_null(ret1); big_set_null(ret2);}
  else {
    big *x, *y;

    big_init_m(2, &x, &y);
    big_alloc_len(&x, p1->len);
    big_alloc_len(&y, p2->len);

    big_copy(p1, &x);
    big_copy(p2, &y);

    big_copy(x, ret1);
    y->neg = true;
    big_mod(y, curve_p, ret2);

    // assert on_curve(ret1, ret2)
    //big_end_m(2, &x, &y);
  }
}

void lc_point_mul(big *key, big *p1, big *p2, big **ret1, big **ret2) {
  big *kcn, *po1, *po2, *two, *addend1, *addend2;

  // assert on_curve(p1, p2)
  big_init_m(4, &kcn, &two, &addend1, &addend2);
  big_alloc_len(&kcn, key->len);
  big_alloc_len(&two, 1);
  big_alloc_max_m(2, &addend1, &addend2);
  //big_set_m(3, &kcn, &addend1, &addend2);
  big_set("2", &two);

  big_mod(key, curve_n, &kcn);
  printf("mul aftr mod\n");
  if (big_cmp_str("0", kcn) == 1 || (p1->null && p2->null)) {
    printf("mul null\n");
    big_set_null(ret1);
    big_set_null(ret2);
  } else if (key->neg == true) {
    printf("mul neg\n");
    big_init_m(2, &po1, &po2);
    big_alloc_len(&po1, p1->len);
    big_alloc_len(&po2, p2->len);
    //big_set_m(2, &po1, &po2);
    key->neg = false;
    lc_point_neg(p1, p1, &po1, &po2);
    lc_point_mul(key, po1, po2, ret1, ret2);
    //big_end_m(2, &po1, &po2);
  } else {
    printf("mul else\n");
    big_set_null(ret1);
    big_set_null(ret2);
    big_copy(p1, &addend1);
    big_copy(p2, &addend2);
    printf("mul else bfr while\n");
    while (big_cmp_str("0", key) == 0) {
      big *k, *r1, *r2, *a1, *a2;

      big_init_m(5, &k, &a1, &a2, &r1, &r2);
      big_alloc_max_m(5, &k, &a1, &a2, &r1, &r2);
      //big_set_m(5, &k, &a1, &a2, &r1, &r2);
      big_alloc_len(&k, key->len);
      printf("mul else in while aftr alloc\n");
      if (big_bit_and_one(key)) {
        printf("mul else in while in if\n");
        lc_point_add(*ret1, *ret2, addend1, addend2, &r1, &r2);
        printf("mul else in while in if aftr add\n");
        big_copy(r1, ret1);
        big_copy(r2, ret2);
      }
      printf("mul else in while aftr if\n");
      lc_point_add(addend1, addend2, addend1, addend2, &a1, &a2);
      big_copy(a1, &addend1);
      big_copy(a2, &addend2);
      big_div(key, two, &k);
      printf("mul else in while aftr div\n");
      big_copy(k, &key);
      //big_end_m(5, &k, &a1, &a2, &r1, &r2);
    }
    // assert on_curve(ret1, ret2)
  }
  //big_end_m(4, &kcn, &two, &addend1, &addend2);
}

void lc_publkey(big *privkey, big **pub1, big **pub2) {
  lc_point_mul(privkey, curve_g1, curve_g2, pub1, pub2);
}

void lc_getrandstr(int len, char *ret) {
  srand(time(0));
  char char1[] = "0123456789";
  for (int i = 0; i < len; i++) {ret[i] = char1[rand() % (sizeof char1 - 1)];}
}

//
// Randomize to a bigint
void lc_random(big **p) {
  char *str = malloc(80);

  lc_getrandstr(80, str);
  big_set(str, &(*p));
  big_end_str(str);
}

//
// Initialize private key
void lc_privkey(big **privkey) {lc_random(privkey);}
