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
#include "lightdefs.h"

//
// Initialize crypt
void lightcrypt_init() {
  printf("Cryptic stuff\n");
  char *s = malloc(512);
  curve_t *c = malloc(sizeof(curve_t));
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

//
// Randomize to a bigint
void lightcrypt_rand(bigint_t **p) {
  char *s = malloc(512);
  srand(time(0));
  sprintf(s, "%llu%llu%llu%llu\n", RAND64(), RAND64(), RAND64(), RAND64());
  big_set(s, &(*p));
  free(s);
}

//
// Randomize to a bigint tuple
void lightcrypt_rand_t(bigtup_t **p) {
  char *s = malloc(512);
  srand(time(0));
  sprintf(s, "%llu%llu%llu%llu\n", RAND64(), RAND64(), RAND64(), RAND64());
  big_set(s, &(*p)->p1);
  sprintf(s, "%llu%llu%llu%llu\n", RAND64(), RAND64(), RAND64(), RAND64());
  big_set(s, &(*p)->p2);
  free(s);
}

//
// Initialize private key
void lightcrypt_privkey(bigint_t **privkey) {
  lightcrypt_rand(privkey);
}

//
// Initialize public key
void lightcrypt_pubkey(bigint_t *privkey, bigtup_t **pubkey) {
  //scalar_mult(privkey, curve.g, pubkey);
}
