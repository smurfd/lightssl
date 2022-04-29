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
// p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
// g1= 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
// g2= 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
// n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
void lightcrypt_init() {
  bigint_t *priv1, *priv2, *publ11, *publ12, *publ21, *publ22;
  big_init_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_init_m(4, &publ11, &publ12, &publ21, &publ22);
  big_alloc_max_m(6, &curve_p, &curve_g1, &curve_g2, &curve_n, &priv1, &priv2);
  big_alloc_max_m(4, &publ11, &publ12, &publ21, &publ22);
  big_set_m(6, &publ11, &publ12, &publ21, &publ22, &priv1, &priv2);
  char *tmpstr = malloc(MAXSTR);

  curve_name = malloc(10);
  big_set("115792089237316195423570985008687907853269984665640564039457584007908834671663", &curve_p);
  big_set("55066263022277343669578718895168534326250603453777594175500187360389116729240", &curve_g1);
  big_set("32670510020758816978083085130507043184471273380659243275938904335757337482424", &curve_g2);
  big_set("115792089237316195423570985008687907852837564279074904382605163141518161494337", &curve_n);
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
      bigint_t *tmp1, *tmp2;

      big_init_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_init_m(2, &tmp1, &tmp2);
      big_alloc_max_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_alloc_max_m(2, &tmp1, &tmp2);
      big_set_m(9, &x3, &y3, &mm, &x1x2, &y1m, &x3x1, &x3m, &r1, &r2);
      big_set_m(2, &tmp1, &tmp2);
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

