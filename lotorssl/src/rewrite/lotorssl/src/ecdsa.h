#ifndef ECDSA_H
#define ECDSA_H 1
#include <stdint.h>
#define u64 unsigned long long int
#define i64 long long int
typedef struct { // rational ec point
  i64 x, y;
} point;

typedef struct { // elliptic curve parameters
  u64 a, b;
  i64 N, r;
  point G;
} curve;

typedef struct { // signature pair
  u64 a, b;
} pair;

int curve_init(curve *e, const long *i);
pair signature(i64 s, long f, curve *e);
int verify(point W, long f, pair sg, curve *e);
int ecdsa(long f, long d, curve *e);
#endif