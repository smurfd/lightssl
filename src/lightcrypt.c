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
  struct curve *c = malloc(sizeof(struct curve)*BIGLEN);

  c->g = malloc(sizeof(bigtup_t));
  big_init_m(4, &(*c).p, &(*c).n, &(*c).g->p1, &(*c).g->p2);
  big_set_m(4, &(*c).p, &(*c).n, &(*c).g->p1, &(*c).g->p2);

  big_init(&a);
  // 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  big_set("115792089237316195423570985008687907853269984665640564039"\
      "457584007908834671663", &a);
  big_copy_ref(a, &(*c).p);

  big_init(&a);
  // 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  big_set("550662630222773436695787188951685343262506034537775941755"\
      "00187360389116729240", &a);
  big_copy_ref(a, &(*c).g->p1);

  big_init(&a);
  // 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  big_set("326705100207588169780830851305070431844712733806592432759"\
      "38904335757337482424", &a);
  big_copy_ref(a, &(*c).g->p2);

  big_init(&a);
  // 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  big_set("115792089237316195423570985008687907852837564279074904382"\
      "605163141518161494337", &a);
  big_copy_ref(a, &(*c).n);

  strcpy((*c).name, "secp256k1");
  (*c).a = 0;
  (*c).b = 7;
  (*c).h = 1;

  big_init(&priv);
  big_set_m(1, &priv);
  lightcrypt_init_t(&publ);
  big_set_m(2, &(*publ).p1, &(*publ).p2);
  lightcrypt_privkey(&priv);
  lightcrypt_pubkey(&(*c), priv, &publ);
  lightcrypt_end_t(&publ);
  big_end(&priv);
  big_end(&a);
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
  big_set_m(2, &(*p)->p1, &(*p)->p2);
}

void lightcrypt_end_t(bigtup_t **p) {
  if ((*p) != NULL) {
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
  char *s = malloc(512);

  srand(time(0));
  sprintf(s, "%llu%llu%llu%llu", RAND64(), RAND64(), RAND64(), RAND64());
  big_init(p);
  big_set(s, &(*p));
  free(s);
}

//
// Randomize to a bigint tuple
void lightcrypt_rand_t(bigtup_t **p) {
  char *s = malloc(512);

  srand(time(0));
  sprintf(s, "%llu%llu%llu%llu", RAND64(), RAND64(), RAND64(), RAND64());
  big_set(s, &(*p)->p1);
  sprintf(s, "%llu%llu%llu%llu", RAND64(), RAND64(), RAND64(), RAND64());
  big_set(s, &(*p)->p2);
  free(s);
}

//
// Initialize private key
void lightcrypt_privkey(bigint_t **privkey) {
//  lightcrypt_rand(privkey);
  big_set("37286503443888916570650794096490365355343842882500054693645072639621059063465", privkey);
  big_print(privkey);
}

//
// Initialize public key
void lightcrypt_pubkey(struct curve *cur, bigint_t *privkey, bigtup_t **pubkey) {
  lightcrypt_point_mul(cur, privkey, cur->g, pubkey);
  // should return:
  // 114228706046720397033883399099126209430656953859958883131997376409144460418386 &
  // 81307239155600299831502865374878345877638639799606025680292741045527875388961
}

//
// Multiplication of points
void lightcrypt_point_mul(struct curve *cur, bigint_t *key, bigtup_t *point,
    bigtup_t **ret) {
  bigint_t *kcn;
  bigtup_t *addend=NULL;

  lightcrypt_init_t(&addend);
  assert(lightcrypt_oncurve(cur, point));
  big_init(&kcn);
  big_set_m(1, &kcn);
  big_mod(key, cur->n, &kcn);
  if ((*kcn).dig[0] == 0 || point == NULL) {
    ret = NULL;
  } else if (key->neg == true) {
    bigtup_t *npoint;
    lightcrypt_init_t(&npoint);
    lightcrypt_point_neg(cur, point, &npoint);
    lightcrypt_point_mul(cur, key, npoint, ret);
    //lightcrypt_end_t(&npoint);
  } else {
    ret = NULL;
    big_set_m(2, &addend->p1, &addend->p2);
    lightcrypt_copy_t(point, &addend);
    while (key) {
      bigint_t *k1, *k2, *t;
      big_init_m(3, &k1, &k2, &t);
      big_set_m(2, &k1, &k2);
      if (big_bit_and_one(key)) {
        bigtup_t *r = NULL;
        lightcrypt_init_t_m(1, &r);
        if (ret != NULL) {
          lightcrypt_copy_t(*ret, &r);
        }
        lightcrypt_point_add(cur, r, addend, ret);
      }
      bigtup_t *ad = NULL;
      lightcrypt_init_t_m(1, &ad);
      lightcrypt_point_add(cur, addend, addend, &ad);
      big_div(key, t, &k2);
      big_copy_ref(k2, &key);
      lightcrypt_copy_t(ad, &addend);
      //big_end_m(3, &t, &k2, &k1);
    }
    assert(lightcrypt_oncurve(cur, *ret));
  }
  //lightcrypt_end_t(&addend);
}

//
// Add two points
void lightcrypt_point_add(struct curve *cur, bigtup_t *point1, bigtup_t *point2,
    bigtup_t **ret) {
  bigint_t *x1, *x2, *y1, *y2, *mmm, *yp2p1, *yp2p2;
  bigtup_t *m=NULL, *y12p=NULL, *cpp=NULL, *yp2p=NULL, *x12pp=NULL, *x12ppp=NULL;
  bool bret = false;

  assert(lightcrypt_oncurve(cur, point1));
  assert(lightcrypt_oncurve(cur, point2));
  big_init_m(7, &x1, &x2, &y1, &y2, &mmm, &yp2p1, &yp2p2);
  lightcrypt_init_t_m(6, &m, &y12p, &cpp, &yp2p, &x12pp, &x12ppp);
  big_set_m(7, &x1, &x2, &y1, &y2, &mmm, &yp2p1, &yp2p2);

  big_copy_ref(point1->p1, &x1);
  big_copy_ref(point1->p2, &y1);
  big_copy_ref(point2->p1, &x2);
  big_copy_ref(point2->p2, &y2);
  if (strcmp(big_get(point1->p1), "0") == 0 && strcmp(big_get(point1->p2),"0") == 0) {
    if (ret == NULL) {
      lightcrypt_init_t_m(1, &ret);
      big_set_m(2, &(*ret)->p1, &(*ret)->p2);
    }
    lightcrypt_copy_t(point2, ret);
    bret = true;
  } else if (strcmp(big_get(point2->p1), "0") == 0 && strcmp(big_get(point2->p2),"0") == 0) {
    lightcrypt_copy_t(point1, ret);
    bret = true;
  } else if (memcmp((*x1).dig, (*x2).dig, (*x1).len*sizeof(int)) == 0 &&
      memcmp((*y1).dig, (*y2).dig, (*x1).len*sizeof(int)) != 0) {
    lightcrypt_copy_t(NULL, ret);
    bret = true;
  }

  if (bret == false) {
    if (x2 != NULL)
    big_clear_zeros(&x2);
    if (x1 != NULL)
    big_clear_zeros(&x1);
    if (memcmp((*x1).dig, (*x2).dig, (*x2).len*sizeof(int))==0) {
      bigint_t *y12, *yp2, *xx1, *xx3, *x3, *xx3ca, *cab;
      char *ca = (char*) malloc(500);

      sprintf(ca, "%d", cur->a);
      big_init_m(6, &y12, &x3, &yp2, &xx1, &xx3, &xx3ca);
      big_set_m(5, &y12, &yp2, &xx1, &xx3, &xx3ca);
      big_set("3", &x3);
      big_set(ca, &cab);
      big_add(y1, y1, &y12); // 2*y1
      lightcrypt_point_imd(cur, &y12, cur->p, &yp2p1);
      big_mul(x1, x1, &xx1); // x1*x1
      big_mul(xx1, x3, &xx3); // 3*x1*x1
      big_add(xx3, cab, &xx3ca);  //
      big_mul(xx3ca, yp2p1, &mmm);
    } else {
      bigint_t *y12, *x12, *x12p;

      big_init_m(3, &y12, &x12, &x12p);
      big_set_m(3, &y12, &x12, &x12p);
      big_sub(x1, x2, &x12);
      big_sub(y1, y2, &y12);
      lightcrypt_point_imd(cur, &y12, cur->p, &yp2p2);
      big_mul(y12, yp2p2, &mmm);
    }
    bigint_t *x12, *mmm2, *mmm2x1, *mmm2x2, *mmm2x31, *mx31, *yx3;
    bigtup_t *mm=NULL, *mm1=NULL, *mm12=NULL, *x3=NULL, *y3=NULL, *x31=NULL, *y1m=NULL;

    big_init_m(7, &x12, &mmm2, &mmm2x1, &mmm2x2, &mmm2x31, &mx31, &yx3);
    big_set_m(7, &x12, &mmm2, &mmm2x1, &mmm2x2, &mmm2x31, &mx31, &yx3);
    lightcrypt_init_t_m(7, &mm, &mm1, &mm12, &x3, &y3, &x31, &y1m);
    big_mul(mmm, mmm, &mmm2);
    big_sub(mmm2, x1, &mmm2x1);
    big_sub(mmm2x1, x2, &mmm2x2); // x3

    big_sub(mmm2x2, x1, &mmm2x31);
    big_mul(mmm, mmm2x31, &mx31);
    big_add(y1, mx31, &yx3); // y3

    yx3->neg = true;
    if (ret == NULL) {
      lightcrypt_init_t_m(1, &ret);
    }
    big_mod(mmm2x2, cur->p, &(*ret)->p1);
    big_mod(yx3, cur->p, &(*ret)->p2);
    assert(lightcrypt_oncurve(cur, *ret));
    lightcrypt_end_t_m(5, &mm, &x3, &y3, &x31, &y1m);
  }
}

//
// Negate the point
void lightcrypt_point_neg(struct curve *cur, bigtup_t *point, bigtup_t **ret) {
  assert(lightcrypt_oncurve(cur, point));
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

    assert(lightcrypt_oncurve(cur, *ret));
//    big_end_m(3, &ycp, &y, &x);
  }
}

//
// Inverse modulo
void lightcrypt_point_imd(struct curve *cur, bigint_t **key, bigint_t *point,
    bigint_t **ret) {
  if ((*key)->dig[0] == 0) {
    printf("ZAROOOO DIVISION\n");
    // Should never happen, division by zero is bad
  }
  if ((*key)->neg == true) {
    bigint_t *r;
    big_init_m(1, &r);
    (*key)->neg=false;
    lightcrypt_point_imd(cur, key, point, &r);
    big_sub(point, r, ret);
  } else {
    bigint_t *r, *s, *t, *or, *os, *ot;

    big_init_m(6, &r, &s, &t, &or, &os, &ot);
    big_set_m(6, &r, &s, &t, &or, &os, &ot);

    big_set("0", &s);
    big_set("1", &os);

    big_set("1", &t);
    big_set("0", &ot);

    big_copy_ref(point, &r);
    big_copy_ref(*key, &or);
    while (strcmp("0", big_get(r)) != 0) {
      bigint_t *q, *qr, *qs, *qt, *ort, *ott, *rt, *st, *tt, *ost;
      big_init_m(10, &q, &qr, &qs, &qt, &ort, &ost, &ott, &rt, &st, &tt);
      big_set_m(10, &q, &qr, &qs, &qt, &ort, &ost, &ott, &rt, &st, &tt);

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
    bigint_t *rr, *ss, *tt, *kss, *kssp;
    big_init_m(5, &rr, &ss, &tt, &kss, &kssp);
    big_set_m(5, &rr, &ss, &tt, &kss, &kssp);

    big_copy_ref(or, &rr);
    big_copy_ref(os, &ss);
    big_copy_ref(ot, &tt);

    assert(strcmp(big_get(rr), "1") == 0);

    big_mul(*key, ss, &kss);
    big_mod(kss, point, &kssp);
    assert(strcmp(big_get(kssp), "1") == 0);

    big_mod(ss, point, ret);
    // FIXME: surviving 1st round, forcing failure to avoid loop, need to figure out why loop?
    assert(1==2);
  }
}

//
// Check if point is on curve
bool lightcrypt_oncurve(struct curve *cur, bigtup_t *point) {
  bool ret = false;
  char *ca = NULL, *cb = NULL;
  bigint_t *x, *y, *res, *res1, *resxx, *resyy, *resxxx, *bca, *bcb;
  big_init_m(9, &x, &y, &res, &res1, &resxx, &resyy, &resxxx, &bca, &bcb);
  big_set_m(7, &x, &y, &res, &res1, &resxx, &resyy, &resxxx);
  if (point == NULL) {
    return true;
  }
  if ((*point).p1 == NULL||(*point).p2 == NULL) {
    return true;
  }
  if (strcmp("0", big_get((*point).p1)) == 0||strcmp("0", big_get((*point).p2)) == 0) {
    return true;
  }
  big_copy_ref(point->p1, &x);
  big_copy_ref(point->p2, &y);
  ca = malloc(512);
  cb = malloc(512);
  sprintf(ca, "%d", cur->a);
  sprintf(cb, "%d", cur->b);
  big_set(ca, &bca);
  big_set(cb, &bcb);
  big_mul(x, x, &resxx);         // x*x
  big_mul(x, resxx, &resxxx);    // (x*x)*x
  big_mul(y, y, &resyy);         // y*y
  big_sub(resyy, resxxx, &res);  // ((y*y)-((x*x)*x))
  big_mul(bca, x, &resxx);       // curve.a*x
  big_sub(res, resxx, &res1);    // ((y*y)-((x*x)*x))-(curve.a*x)
  big_init(&resyy);
  big_sub(res1, bcb, &resyy);    // (((y*y)-((x*x)*x))-(curve.a*x)-curve.b)

  big_init(&res1);
  big_mod(resyy, cur->p, &res1); // % curve.p
  if ((*res1).len == 1 && (*res1).dig[0] == 0) {
    ret = true;
  }
  if (cb) {
    free(cb);
  }
  if (ca) {
    free(ca);
  }
  //big_end_m(9, &bcb, &bca, &resxxx, &resyy, &resxx, &res1, &res, &y, &x);
  return ret;
}
