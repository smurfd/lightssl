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
  printf("Cryptic stuff\n");
  bigint_t *priv;
  bigtup_t *publ = NULL;
  char *s = malloc(512);
  struct curve *c = malloc(sizeof(struct curve));
  c->g = malloc(sizeof(bigtup_t));
  bigint_t *a;
  big_init(&(c->p));
  big_init(&(c->n));

  big_init(&a);
  // 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  big_set("115792089237316195423570985008687907853269984665640564039457584007908834671663", &a);
  (*c).p = a;

  big_init(&a);
  // 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  big_set("55066263022277343669578718895168534326250603453777594175500187360389116729240", &a);
  (*c).g->p1 = a;

  big_init(&a);
  // 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  big_set("32670510020758816978083085130507043184471273380659243275938904335757337482424", &a);
  (*c).g->p2 = a;

  big_init(&a);
  // 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  big_set("115792089237316195423570985008687907852837564279074904382605163141518161494337", &a);
  (*c).n = a;

  strcpy((*c).name, "secp256k1");
  (*c).a = 0;
  (*c).b = 7;
  (*c).h = 1;

  big_print(&(*c).p);
  big_print(&(*c).g->p1);
  big_print(&(*c).g->p2);
  big_print(&(*c).n);
  lightcrypt_rand_t(&(*c).g);

  big_print(&(*c).g->p1);
  big_print(&(*c).g->p2);
  big_init(&priv);
  big_set("", &priv);
  lightcrypt_init_t(&publ);
  lightcrypt_privkey(&priv);
  big_print(&priv);

  lightcrypt_pubkey(&(*c), priv, &publ);
  lightcrypt_end_t(&publ);
  big_end(&priv);
  big_end(&a);
  if (c) {
    free(c);
  }
  if (c->g) {
    free(c->g);
  }
  if (s) {
    free(s);
  }
}

void lightcrypt_init_t(bigtup_t **p) {
  (*p) = malloc(sizeof(bigtup_t));
  big_set_m(2, &(*p)->p1, &(*p)->p2);
}

void lightcrypt_end_t(bigtup_t **p) {
  free((*p));
}

void lightcrypt_init_t_m(int len, ...) {
  va_list valist;
  va_start(valist, len);
  for (int i=0; i<len; i++) {
    lightcrypt_init_t(va_arg(valist, bigtup_t**));
  }
  va_end(valist);
}

void lightcrypt_end_t_m(int len, ...) {
  va_list valist;
  va_start(valist, len);
  for (int i=0; i<len; i++) {
    lightcrypt_end_t(va_arg(valist, bigtup_t**));
  }
  va_end(valist);
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
  lightcrypt_rand(privkey);
  big_print(privkey);
}

//
// Initialize public key
void lightcrypt_pubkey(struct curve *cur, bigint_t *privkey, bigtup_t **pubkey) {
  lightcrypt_point_mul(cur, privkey, cur->g, pubkey);
}

//
// Multiplication of points
void lightcrypt_point_mul(struct curve *cur, bigint_t *key, bigtup_t *point, bigtup_t **ret) {
  bigint_t *kcn;
  bigtup_t *addend=NULL;

  lightcrypt_init_t(&addend);
  assert(lightcrypt_oncurve(cur, point));
  big_init(&kcn);
  big_set("", &kcn);
  big_mod(key, cur->n, &kcn); // this causes endless loop?
  if ((*kcn).dig[0] == 0 || point == NULL) {
    ret = NULL;
  } else if (key->neg == true) {
    bigtup_t *npoint;
    lightcrypt_init_t(&npoint);
    lightcrypt_point_neg(cur, point, &npoint);
    lightcrypt_point_mul(cur, key, npoint, ret);
    lightcrypt_end_t(&npoint);
  } else {
    ret = NULL;
    addend = point;
    while (key) {
      bigint_t *k1, *k2, *t;
      big_init_m(3, &k1, &k2, &t);
      big_set_m(2, &k1, &k2);
      big_set("2", &t);
      big_mod(key, t, &k1);
      if (k1) {
        lightcrypt_point_add(cur, *ret, addend, ret);
      }
      lightcrypt_point_add(cur, addend, addend, &addend);
      big_div(key, t, &k2);
      (*key) = (*k2);
      big_end_m(3, &t, &k2, &k1);
    }
    assert(lightcrypt_oncurve(cur, *ret));
  }
  lightcrypt_end_t(&addend);
}

//
// Add two points
void lightcrypt_point_add(struct curve *cur, bigtup_t *point1, bigtup_t *point2, bigtup_t **ret) {
  bigint_t *x1, *x2, *y1, *y2;
  bigtup_t *m=NULL, *y12p=NULL, *cpp=NULL, *yp2p=NULL, *x12pp=NULL, *x12ppp=NULL;
  assert(lightcrypt_oncurve(cur, point1));
  assert(lightcrypt_oncurve(cur, point2));
  big_init_m(4, &x1, &x2, &y1, &y2);
  lightcrypt_init_t_m(6, &m, &y12p, &cpp, &yp2p, &x12pp, &x12ppp);
  big_set_m(4, &x1, &x2, &y1, &y2);

  (*x1) = *(*point1).p1;
  (*y1) = *(*point1).p2;
  (*x2) = *(*point2).p1;
  (*y2) = *(*point2).p2;
  (*cpp).p1 = curve_t.p;
  (*cpp).p2 = NULL;

  if (point1 == NULL) {
    (*ret) = point2;
  } else if (point2 == NULL) {
    (*ret) = point1;
  } else if ((*x1).dig == (*x2).dig && !((*y1).dig == (*y2).dig)) {
    (*ret) = NULL;
  } else if ((*x1).dig == (*x2).dig) {
    bigint_t *y12, *yp2, *xx1, *xx3, *x3, *xx3ca, *cab;
    char *ca = NULL;
    sprintf(ca, "%d", cur->a);
    big_init_m(6, &y12, &x3, &yp2, &xx1, &xx3, &xx3ca);
    big_set_m(5, &y12, &yp2, &xx1, &xx3, &xx3ca);
    big_set("3", &x3);
    big_set(ca, &cab);
    big_add(y1, y1, &y12); // 2*y1
    (*y12p).p1 = y12;
    (*y12p).p2 = NULL;
    lightcrypt_point_imd(cur, y12p, cpp, &yp2p);
    big_mul(x1, x1, &xx1); // x1*x1
    big_mul(xx1, x3, &xx3); // 3*x1*x1
    big_add(xx3, cab, &xx3ca);  //
    big_mul(xx3ca, yp2p->p1, &m->p1);
    big_mul(xx3ca, yp2p->p2, &m->p2);
    big_end_m(6, &xx3ca, &xx3, &xx1, &yp2, &x3, &y12);
  } else if ((*x1).dig != (*x2).dig) {
    bigint_t *y12, *x12, *x12p;
    big_init_m(3, &y12, &x12, &x12p);
    big_set_m(3, &y12, &x12, &x12p);
    big_sub(x1, x2, &x12);
    big_sub(y1, y2, &y12);
    (*x12pp).p1 = y12;
    (*x12pp).p2 = NULL;
    lightcrypt_point_imd(cur, x12pp, cpp, &x12ppp);
    big_mul(y12, x12ppp->p1, &m->p1);
    big_mul(y12, x12ppp->p2, &m->p2);
    big_end_m(3, &x12p, &x12, &y12);
  } else {
    bigint_t *x12;
    bigtup_t *mm=NULL, *x3=NULL, *y3=NULL, *x31=NULL, *y1m=NULL;
    big_init(&x12);
    big_set("", &x12);
    lightcrypt_init_t_m(5, &mm, &x3, &y3, &x31, &y1m);
    big_sub(x1, x2, &x12);
    big_mul(m->p1, m->p1, &mm->p1);
    big_mul(m->p2, m->p2, &mm->p2);
    big_sub(mm->p1, x12, &x3->p1); // x3
    big_sub(mm->p2, x12, &x3->p2); // x3
    big_sub(x3->p1, x1, &x31->p1);
    big_sub(x3->p2, x1, &x31->p2);
    big_mul(m->p1, x31->p1, &y1m->p1);
    big_mul(m->p2, x31->p2, &y1m->p2);
    big_add(y1, y1m->p1, &y3->p1); // y3
    big_add(y1, y1m->p2, &y3->p2); // y3
    y3->p1->neg = true;
    y3->p2->neg = true;
    big_mod(x3->p1, cur->p, &(*ret)->p1);
    big_mod(y3->p1, cur->p, &(*ret)->p2);
    lightcrypt_end_t_m(5, &mm, &x3, &y3, &x31, &y1m);
    big_end(&x12);
  }
  lightcrypt_end_t_m(6, &m, &y12p, &cpp, &yp2p, &x12pp, &x12ppp);
  big_end_m(4, &y2, &y1, &x2, &y1);
  assert(lightcrypt_oncurve(cur, *ret));
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

    (*x) = *(*point).p1;
    (*y) = *(*point).p2;

    (*ret)->p1 = x;
    (*y).neg = true;
    big_mod(y, cur->p, &ycp);
    (*ret)->p2 = ycp;

    assert(lightcrypt_oncurve(cur, *ret));
    big_end_m(3, &ycp, &y, &x);
  }
}

//
// Inverse modulo
void lightcrypt_point_imd(struct curve *cur, bigtup_t *key, bigtup_t *point, bigtup_t **ret) {
  if (key->p1->dig[0] == 0 && key->p2->dig[0] == 0) {
    // Should never happen, division by zero is bad
  }

  if (key->p1->neg || key->p2->neg) {
    bigtup_t *r = NULL;
    lightcrypt_init_t_m(1, &r);
    key->p1->neg = true;
    key->p2->neg = true;
    lightcrypt_point_imd(cur, key, point, &r);
    big_sub(point->p1, r->p1, &(*ret)->p1);
    big_sub(point->p2, r->p2, &(*ret)->p2);
    lightcrypt_end_t_m(1, &r);
  } else {
    bigtup_t *r = NULL, *s = NULL, *t = NULL, *or = NULL, *os = NULL, *ot = NULL;
    lightcrypt_init_t_m(6, &r, &s, &t, &or, &os, &ot);
    big_set("0", &(*s).p1);
    big_set("0", &(*s).p2);
    big_set("1", &(*os).p1);
    big_set("1", &(*os).p2);

    big_set("1", &(*t).p1);
    big_set("1", &(*t).p2);
    big_set("0", &(*ot).p1);
    big_set("0", &(*ot).p2);
    (*r).p1 = (*point).p1;
    (*r).p2 = (*point).p2;
    (*or).p1 = (*key).p1;
    (*or).p2 = (*key).p2;

    while(r->p1->dig[0] != 0 && r->p2->dig[0] != 0) {
      bigtup_t *q = NULL, *qr = NULL, *qs = NULL, *qt = NULL, *ort = NULL, *ost = NULL;
      bigtup_t *ott = NULL, *rt = NULL, *st = NULL, *tt = NULL;
      lightcrypt_init_t_m(10, &qr, &qs, &qt, &ort, &ost, &ott, &rt, &st, &tt);
      big_div(or->p1, r->p1, &q->p1);
      big_div(or->p2, r->p2, &q->p2);
      (*ort) = (*or);
      (*ost) = (*os);
      (*ott) = (*ot);
      (*rt) = (*r);
      (*st) = (*s);
      (*tt) = (*t);

      (*or) = (*r);
      (*os) = (*s);
      (*ot) = (*t);

      big_mul(q->p1, rt->p1, &qr->p1);
      big_mul(q->p2, rt->p2, &qr->p2);
      big_mul(q->p1, st->p1, &qs->p1);
      big_mul(q->p2, st->p2, &qs->p2);
      big_mul(q->p1, tt->p1, &qt->p1);
      big_mul(q->p2, tt->p2, &qt->p2);

      big_sub(ort->p1, qr->p1, &r->p1);
      big_sub(ort->p2, qr->p2, &r->p2);
      big_sub(ost->p1, qs->p1, &s->p1);
      big_sub(ost->p2, qs->p2, &s->p2);
      big_sub(ott->p1, qt->p1, &t->p1);
      big_sub(ott->p2, qt->p2, &t->p2);
      lightcrypt_end_t_m(10, &qr, &qs, &qt, &ort, &ost, &ott, &rt, &st, &tt);
    }
    bigtup_t *rr = NULL, *ss = NULL, *tt = NULL, *kss = NULL, *kssp = NULL;
    lightcrypt_init_t_m(5, &rr, &ss, &tt, &kss, &kssp);
    (*rr) = (*or);
    (*ss) = (*os);
    (*tt) = (*ot);
    assert(rr->p1->dig[0] == 1);
    assert(rr->p2->dig[0] == 1);

    big_mul(key->p1, ss->p1, &kss->p1);
    big_mul(key->p2, ss->p2, &kss->p2);
    big_mod(kss->p1, point->p1, &kssp->p1);
    big_mod(kss->p2, point->p2, &kssp->p2);
    assert(kssp->p1->dig[0] == 1);
    assert(kssp->p2->dig[0] == 1);

    big_mod(ss->p1, point->p1, &(*ret)->p1);
    big_mod(ss->p2, point->p2, &(*ret)->p2);
    lightcrypt_end_t_m(5, &rr, &ss, &tt, &kss, &kssp);
    lightcrypt_end_t_m(6, &r, &s, &t, &or, &os, &ot);
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
  (*x) = *(*point).p1;
  (*y) = *(*point).p2;
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
  big_sub(res1, bcb, &resyy);    // (((y*y)-((x*x)*x))-(curve.a*x)-curve.b)
  big_print(&resyy);
  big_print(&cur->p);
  printf("endless loop next step... why?\n");
  big_mod(resyy, cur->p, &res1); // % curve.p
  if ((*res1).len == 1 && (*res1).dig[0] == 0) {
    ret = true;
  }
  big_end_m(9, &bcb, &bca, &resxxx, &resyy, &resxx, &res1, &res, &y, &x);
  return ret;
}
