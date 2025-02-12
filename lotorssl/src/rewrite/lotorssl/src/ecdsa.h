#ifndef ECDSA_H
#define ECDSA_H 1
#include <stdint.h>
#define u64 unsigned long long int
#define i64 long long int
static const i64 zeroXY[2] = {-2147483647, 0}; // infinity
static const u64 mxNr[2] = {1073741789, 1073807325}; // mxN = maximum modulus, mxr = max order G = mxN + 65536
typedef struct { // rational ec point
  i64 x, y;
} point;

typedef struct { // elliptic curve parameters
  u64 a, b;
  i64 N, r;
  point G;
  int inverr;
} curve;

typedef struct { // signature pair
  u64 a, b;
} pair;

int curve_init(curve *e, const long *i);
pair signature(i64 s, long f, curve *e);
int verify(point W, long f, pair sg, curve *e);
int ecdsa(long h, long d, curve *e);
#endif
