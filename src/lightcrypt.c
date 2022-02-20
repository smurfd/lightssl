//                                                                            //
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include "lightcrypt.h"
#include "lightdefs.h"

//
// Initialize crypt
void lightcrypt_init() {
  bigint_t *priv, *a;
  bigtup_t *publ = NULL;
  char *s = malloc(512);
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
  lightcrypt_privkey(&priv);
  lightcrypt_pubkey(&(*c), priv, &publ);
  printf("pub : %s, %s\n", big_get((*publ).p1), big_get((*publ).p2));

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

//
// Initialize private key
void lightcrypt_privkey(bigint_t **privkey) {
//  lightcrypt_rand(privkey);
  big_set("372865034438889165706507940964903653553438428825000546936"\
      "45072639621059063465", privkey);
  big_print(privkey);
}

//
// Initialize public key
void lightcrypt_pubkey(struct curve *cur, bigint_t *privkey,
    bigtup_t **pubkey) {
  lightcrypt_point_mul(cur, privkey, cur->g, pubkey);
  //printf("PUBK: (%s, %s)\n", big_get((*pubkey)->p1), big_get((*pubkey)->p2));
  // should return(from python ecdhe.py):
  // 114228706046720397033883399099126209430656953859958883131997376409144460418386,
  // 81307239155600299831502865374878345877638639799606025680292741045527875388961
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
    while (strcmp(big_get(key), "0") != 0) {
      printf("key1 = %s\n", big_get(key));
      if (big_bit_and_one(key)) {
        if (ret != NULL) {
          lightcrypt_copy_t(*ret, &r);
        }
        lightcrypt_point_add(cur, r, addend, ret);
      }
      printf("key2 = %s\n", big_get(key));
      lightcrypt_point_add(cur, addend, addend, &ad);
      printf("key3 = %s\n", big_get(key));
      // FIXME: malloc: Region cookie corrupted between this print and next
      big_div(key, t, &k2);
      printf("key4 = %s\n", big_get(key));
      big_copy_ref(k2, &key);
      printf("key5 = %s\n", big_get(key));
      lightcrypt_copy_t(ad, &addend);
      printf("key6 = %s\n", big_get(key));
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
  if (strcmp(big_get(point1->p1), "0") == 0 && strcmp(big_get(
        point1->p2), "0") == 0) {
    if (ret == NULL) {
      lightcrypt_init_t_m(1, &ret);
    }
    lightcrypt_copy_t(point2, ret);
    bret = true;
  } else if (strcmp(big_get(point2->p1), "0") == 0 &&
        strcmp(big_get(point2->p2), "0") == 0) {
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

    yx3->neg = true;
    lightcrypt_init_t_m(1, &ret);
    big_mod(mmm2x2, cur->p, &(*ret)->p1);
    big_mod(yx3, cur->p, &(*ret)->p2);
    printf("ret (%s, %s)\n", big_get((*ret)->p1), big_get((*ret)->p2));
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

    while (strcmp("0", big_get(r)) != 0) {
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
  if (strcmp("0", big_get((*point).p1)) == 0||strcmp("0",
      big_get((*point).p2)) == 0) {
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
