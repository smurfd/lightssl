// https://rosettacode.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "ecdsa.h"

// i64 for holding intermediate results, long variables in exgcd() for efficiency, maximum parameter size 2 * p.y limits the modulus size to 30 bits.
static inline long exgcd(curve *e, const long vv, const long uu) { // return mod(v^-1, u)
  register long q, t, r = 0, s = 1, v = vv, u = uu;
  if (v < 0) v += u;
  while (v) {
    q = u / v;
    t = u - q * v;
    u = v;
    v = t;
    t = r - q * s;
    r = s;
    s = t;
  }
  if (u != 1) {e->inverr = 1; return -1;} // impossible inverse mod N, gcd = u
  return r;
}

// return mod(a, N)
static inline i64 mod_n(i64 a, const curve *e) {
  if ((a %= e->N) < 0) a += e->N;
  return a;
}

// return mod(a, r)
static inline i64 mod_r(i64 a, const curve *e) {
  if ((a %= e->r) < 0) a += e->r;
  return a;
}

// return the discriminant of E
static inline long disc(const curve *e) {
  i64 a = e->a, b = e->b, c = 4 * mod_n(a * mod_n(a * a, e), e);
  return mod_n(-16 * (c + 27 * mod_n(b * b, e)), e);
}

// return 1 if P = zerO
static inline bool point_zero(const point p) {
  return (p.x == zeroXY[0]) && (p.y == zeroXY[1]);
}

// return 1 if P is on curve E
static inline bool point_oncurve(const point p, const curve *e) {
  long r = 0, s = 0;
  if (!point_zero(p)) {
    r = mod_n(e->b + p.x * mod_n(e->a + p.x * p.x, e), e);
    s = mod_n(p.y * p.y, e);
  }
  return (r == s);
}

// full ec point addition
static inline void point_add(point *r, const point p, const point q, const curve *e) {
  point zerO; zerO.x = zeroXY[0]; zerO.y = zeroXY[1];
  i64 la, t;
  if (point_zero(p)) {*r = q; return;}
  if (point_zero(q)) {*r = p; return;}
  if (p.x != q.x) { // R:= P + Q
    t = p.y - q.y;
    la = mod_n(t * exgcd((curve*)e, p.x - q.x, e->N), e);
  } else { // P = Q, R := 2P
    if ((p.y == q.y) && (p.y != 0)) {
      t = mod_n(3 * mod_n(p.x * p.x, e) + e->a, e);
      la = mod_n(t * exgcd((curve*)e, 2 * p.y, e->N), e);
    } else { // P = -Q, R := O
      *r = zerO;
      return;
    }
  }
  t = mod_n(la * la - p.x - q.x, e);
  r->y = mod_n(la * (p.x - t) - p.y, e);
  r->x = t;
  if (e->inverr) *r = zerO;
}

// R:= multiple kP
static inline void point_mul(point *r, const point p, const long k, const curve *e) {
  point zerO, s, q = p; zerO.x = zeroXY[0]; zerO.y = zeroXY[1]; s = zerO;
  for (long i = k; i; i >>= 1) {
    if (i & 1) point_add(&s, s, q, e);
    if (e->inverr) {s = zerO; break;}
    point_add(&q, q, q, e);
  }
  *r = s;
}

// random number [0..1]
static inline double rnd(void) {
  uint32_t r, f = open("/dev/urandom", O_RDONLY);
  read(f, &r, sizeof r);
  close(f);
  return r / (2 * (double)RAND_MAX + 1);
}

// initialize elliptic curve
int curve_init(curve *e, const long *i) {
  long a = i[0], b = i[1];
  e->inverr = 0;
  e->N = i[2];
  if ((e->N < 5) || (e->N > mxNr[0])) return 0;
  e->a = mod_n(a, e);
  e->b = mod_n(b, e);
  e->G.x = mod_n(i[3], e);
  e->G.y = mod_n(i[4], e);
  e->r = i[5];
  if ((e->r < 5) || (e->r > mxNr[1])) return 0;
  return 1;
}

// signature primitive
pair signature(i64 s, long f, curve *e) {
  long c = 0, d = 0, u = 0;
  pair sg;
  point V;
  while (d == 0) {
    while (1) {
      u = 1 + (long)(rnd() * (e->r - 1));
      point_mul(&V, e->G, u, e);
      if ((c = mod_r(V.x, e)) != 0) break;
    }
    d = mod_r(exgcd(e, u, e->r) * (f + mod_r(s * c, e)), e);
  }
  sg.a = c; sg.b = d;
  return sg;
}

// verification primitive
int verify(point W, long h, pair sg, curve *e) {
  long c = sg.a, d = sg.b;
  i64 f;
  point V, V2;
  // domain check
  if (!((c > 0) && (c < e->r)) & ((d > 0) && (d < e->r))) return 0;
  f = exgcd(e, d, e->r);
  point_mul(&V, e->G, mod_r(h * f, e), e);
  point_mul(&V2, W, mod_r(c * f, e), e);
  point_add(&V, V, V2, e);
  if (point_zero(V)) return 0;
  return (mod_r(V.x, e) == c);
}

// digital signature on message hash f, error bit d
int ecdsa(long h, long d, curve *e) {
  point W;
  // parameter check
  long t = (disc(e) == 0);
  t |= point_zero(e->G);
  point_mul(&W, e->G, e->r, e);
  t |= !point_zero(W);
  t |= !point_oncurve(e->G, e);
  if (t) return -1;  // invalid parameter set
  long s = 1 + (long)(rnd() * (e->r - 1));
  point_mul(&W, e->G, s, e);
  // next highest power of 2 - 1
  t = e->r;
  for (long i = 1; i < 32; i <<= 1) t |= t >> i;
  while (h > t) h >>= 1;
  pair sg = signature(s, h, e);
  if (e->inverr) return -1;
  if (d > 0) {
    while (d > t) d >>= 1;
    h ^= d; // f = corrupted hash
  }
  if (verify(W, h, sg, e)) {
    if (e->inverr) return -1;
    return 0;
  } // if valid return 0
  return -1;
}
