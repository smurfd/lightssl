// Auth: smurfd, 2025 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <math.h>
#include "../../../lighthash.h"
#include "ecc.h"

static inline void u64rnd_array(uint8_t *h, u64 *k, const int len) {
  u64 f7 = 0x7fffffffffffffff;
  int r[2*len], f = open("/dev/urandom", O_RDONLY);
  int rr = read(f, &r, sizeof r);
  close(f);
  if (rr >= 0)
  for (int i = 0; i < len; ++i) {
    h[i] = (uint8_t)(r[i] & f7);
    k[i] = (u64)(r[i] & f7);
  }
}

static inline u64 u64rnd(void) {
  u64 f7 = 0x7fffffffffffffff;
  int r[5], f = open("/dev/urandom", O_RDONLY);
  int rr = read(f, &r, sizeof r);
  close(f);
  if (rr < 0) return -1;
  return (r[0] & f7) << 48 ^ (r[1] & f7) << 35 ^ (r[2] & f7) << 22 ^ (r[3] & f7) << 9 ^ (r[4] & f7) >> 4;
}

static inline void big_endian_uint32(uint8_t *a, const uint32_t value) {
  a[0] = (value >> 24) & 0xff;
  a[1] = (value >> 16) & 0xff;
  a[2] = (value >> 8) & 0xff;
  a[3] = (value >> 0) & 0xff;
}

static inline uint32_t read_big_endian_uint32(const uint8_t *a) {
  return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

// https://datatracker.ietf.org/doc/html/rfc6979
static inline uint32_t bits2int(const uint8_t *q, const uint32_t blen, const uint32_t qlen) {
  uint8_t ret[32] = {0};
  u64 r = 0;
  if (qlen < blen) memcpy(ret, q, qlen);
  else {
    memset(ret, 0, qlen - blen);
    memcpy(ret + (qlen - blen), q, qlen);
  }
  for (int co = 0, i = qlen - 1; i >= 0; i--) {
    r += ret[co++] * (2 ^ i);
    //r += ret[i - (qlen - 1)] * (2 ^ i);
  }
  printf("R: %llu\n", r);
  return r;
}

/*
uint8_t isPrime(uint32_t n) {
  if (n <= 1) return 0;
  if (n == 2) return 1;
  if (n % 2 == 0) return 0;
  for (int i = 3; i <= sqrt(n); i += 2) {
    if (n % i == 0) return 0;
  }
  return 1;
}
*/

static inline void int2octets(uint8_t *r, const uint32_t value) {
  //uint32_t rlen = 8 * ceil(qlen / 8);
  big_endian_uint32(r, value);
}

// q = big prime = UINT32_MAX/2 for now
static inline void bits2octets(uint8_t *o, const uint8_t *b, const uint32_t q, const uint32_t blen, const uint32_t qlen) {
  uint32_t z1 = bits2int(b, blen, qlen), z2 = MOD(z1, q);
  int2octets(o, z2);
}

static inline void ecc_hmac(uint32_t knew, const char *msg, const uint32_t q) {
  uint8_t h1[512] = {0}, V[512] = {0}, K[512] = {0}, Vcat[512] = {0}, xo[512] = {0}, h1o[512] = {0}, T[512] = {0}, k[512] = {0}, Ttmp[512] = {0};
  uint32_t x = 0x31337, tlen = 0, qlen = 32; // x = private key
  hash_new((char*)h1, (uint8_t*)msg);
  memset(V, 0x01, 32); // 8 * ceil(hlen / 8)
  memset(K, 0x00, 32); // 8 * ceil(hlen / 8)
  int2octets(xo, x);
  bits2octets(h1o, h1, q, 32, 32);
  // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
  memcpy(Vcat, V, 32); // TODO: Concatinaton!?
  memset(Vcat + 32, 0x00, 1);
  memcpy(Vcat + 32 + 1, xo, 8);
  memcpy(Vcat + 32 + 1 + 8, h1o, 8);
  hash_new((char*)k, (uint8_t*)Vcat); // TOOD: we are not using k when hashing
  hash_new((char*)V, (uint8_t*)V); // TOOD: we are not using k when hashing
  while (tlen < qlen) {
    hash_new((char*)V, (uint8_t*)V);
    if (tlen == 0) memset(T, 0, 1);
    else {
      memcpy(Ttmp, T, tlen);
      memcpy(T, Ttmp, tlen);
    }
    memcpy(T + tlen, V, qlen);
    tlen += 32;
    knew = bits2int(T, 32, 32);
  }
  if (q < knew) {printf("need to loop hmac again\n");} // TODO: actually loop until k is smaller than q
}

// E    an elliptic curve, defined over a given finite field
// q    a sufficiently large prime number (at least 160 bits) that is a divisor of the curve order
// G    a point of E, of order q
// qG = 0
static inline void ecc_signgen(uint32_t r, uint32_t s, const char *msg) {
  char hash[512] = {""};
  uint8_t gg[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  hash_new((char*)hash, (uint8_t*)msg);
  uint32_t knew = 0, q = UINT32_MAX/2, h = MOD(bits2int((uint8_t*)hash, 32, 32), q), k = 0, x = 0x31337; // x = private key
  while (k == 0) {k = MOD(u64rnd(), q);} // K, shall never be 0
  printf("K=%u\n", k);
  r = MOD(bits2int(gg, 32, 32), q); // TODO: fix length
  uint32_t s1 = (h + x * r)/k;
  s = MOD(s1, q);
  printf("sig: %u, %u\n", r, s);
  ecc_hmac(knew, msg, q);
  printf("Knew=%u\n", knew);
}

// montgomerys ladder
// Pt multiplication
// curve E: (y*y) = (x*x*x) + ax + b
void ecc_pt_add(pt R, pt P, pt Q) {
  //u64 yt = (Q.y - P.y) / (Q.x - P.x);
  //R.x = yt*yt - P.x - Q.x;
  //R.y = yt*(P.x - R.x) - P.y;
  u64 yt[6] = {0};
  for (int i = 0; i < 6; i++) {
    yt[i] = (Q.y[i] - P.y[i]) / (Q.x[i] - P.x[i]);
    R.x[i] = yt[i]*yt[i] - P.x[i] - Q.x[i];
    R.y[i] = yt[i]*(P.x[i] - R.x[i]) - P.y[i];
  }
}

void ecc_pt_double(pt R, pt P) {
  pt tmp;
  memcpy(tmp.x, P.x, 6 * sizeof(u64));
  memcpy(tmp.y, P.y, 6 * sizeof(u64));
  ecc_pt_add(R, tmp, tmp);
}

void ecc_pt_multiplication(pt R0, pt R1, pt P) {
  int m = 6, di = 1;
  pt *Ptmp = malloc(sizeof(struct pt));
  memset(R0.x, 0, 6 * sizeof(u64));
  memset(R0.y, 0, 6 * sizeof(u64));
  memcpy(R1.x, P.x, 6 * sizeof(u64));
  memcpy(R1.y, P.y, 6 * sizeof(u64));
  for (int i = m; i >= 0; i--) {
    if (di == 0) {
      ecc_pt_add(R1, R0, R1);
      ecc_pt_double(R0, R0);
    } else {
      ecc_pt_add(R0, R0, R1);
      ecc_pt_double(R1, R1);
    }
    ecc_pt_add(*Ptmp, R0, P);
    //assert(memcmp(&R1, &Ptmp, sizeof(struct pt)) == 0);
  }
  free(Ptmp);
}

// For Alice to sign a message m, she follows these steps:
//   1. Calculate e = HASH(m), // HASH is a crypto hash function like SHA2, with the output converted to an int.
//   2. Let z be the leftmost Ln bits of e, where Ln is the bit length of group order n (z can be greater but not longer than n)
//   3. Select a cryptographically secure random int k from [1, n-1]
//   4. Calculate the curve point (x1, y1) = k x G
//   5. Calculate r = x1 mod n. If r == 0, goto step 3
//   6. Calculate s = k-1(z + rda) mod n. If s == 0, goto step 3
//   7. The signature is the pair (r, s). And (r, -s mod n) is also a valid signature
// L = 3072, N = 256 (3072 / 8 = 384)
void ecc_sign_gen(void) {
  char e[384] = {0}, hash[666] = {0};
  pt *curvep = malloc(sizeof(struct pt)), *curveg = malloc(sizeof(struct pt)), *pk = malloc(sizeof(struct pt));
  u64 k[6] = {0}, rr[6] = {0}, r = 1, s[6] = {0}, st[6] = {0}, n[] = {0xecec196accc52973, 0x581a0db248b0a77a,
  0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, rda[6] = {0}, privkey[6] = {0}, zrda[6] = {0}, stzrda[6] = {0};
  uint8_t h[6] = {0}, h2[6] = {0}, z[384] = {0};
  hash_new((char*)hash, (uint8_t*)"some string to hash");
  memcpy(e, hash, 384);
  memcpy(z, hash, 384);
  curveg->x[0] = 0x3a545e3872760ab7;
  curveg->x[1] = 0x5502f25dbf55296c;
  curveg->x[2] = 0x59f741e082542a38;
  curveg->x[3] = 0x6e1d3b628ba79b98;
  curveg->x[4] = 0x8eb1c71ef320ad74;
  curveg->x[5] = 0xaa87ca22be8b0537;

  curveg->y[0] = 0xaa87ca22be8b0537;
  curveg->y[1] = 0x0a60b1ce1d7e819d;
  curveg->y[2] = 0xe9da3113b5f0b8c0;
  curveg->y[3] = 0xf8f41dbd289a147c;
  curveg->y[4] = 0x5d9e98bf9292dc29;
  curveg->y[5] = 0x3617de4a96262c6f;

  while (r != 0) {
    u64rnd_array(h, k, 6);
    u64rnd_array(h2, privkey, 6);
    ecc_pt_multiplication(*pk, *curvep, *curveg); //incorrect curveg
    curvep->x[1] = (curveg->x[1] * k[1]);
    curvep->y[1] = (curveg->y[1] * k[1]);
    for (int i = 0; i < 6; i++) {
      rr[i] = MOD(curvep->x[i], n[i]);
    }
    if (r != 0) {
      for (int i = 0; i < 6; i++) {
        st[i] = pow(k[i], -1);
        rda[i] = privkey[i] * rr[i];//r;
        zrda[i] = z[i] + rda[i];
        stzrda[i] = st[i] * zrda[i];
        s[i] = MOD(stzrda[i], n[i]);
        printf("s: %llu, %llu, %llu, %llu %llu\n", st[i], rda[i], zrda[i], stzrda[i], s[i]);
      }
      r = 0;
    }
  }
  free(curvep);
  free(curveg);
  free(pk);
  // signature: rr, s ??
  for (int i = 0; i < 6; i++) {
    printf("sig: %llu, %llu: %llu, %llu, %d %hhu %llu\n", rr[i], s[i], privkey[i], k[i], hash[i], z[i], rda[i]);
  }
  uint32_t r1 = 0, s1 = 0;
  ecc_signgen(r1, s1, "some string to hash");
  //printf("sig: %lu, %lu\n", r1, s1);
}
// ECDSA
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// https://www.rfc-editor.org/rfc/rfc6979
// https://www.rfc-editor.org/rfc/rfc4050
// https://datatracker.ietf.org/doc/html/rfc6979

// https://aaronbloomfield.github.io/ccc/slides/encryption.html#/3/1
