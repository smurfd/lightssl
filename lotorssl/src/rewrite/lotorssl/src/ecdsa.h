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

// docs from wikipedia:
//      Signature generation                  Signature verification
//               |                                     |
//           hash function                         hash function
//               |                                     |
//        message digest                        message digest
//               |                                     |
// --- priv key v                 public key v
//      Signature generation                  Signature verification
//                    v                                         v
//                      --- signature  ----                        valid?

// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
//
// Signature generation algorithm
// CURVE   the elliptic curve field and equation used
// G       elliptic curve base point, a point on the curve that generates a subgroup of large prime order n
// n       integer order of G, means that n × G = O, where O is the identity element.
// dA      the private key (randomly selected)
// QA      the public key d A × G (calculated by elliptic curve)
// m       the message to send

// The order n of the base point G must be prime. We assume every nonzero element of the ring Z/nZ is invertible
// so Z/nZ must be a field, which implies n must be prime

// Alice creates a key pair, consisting of a private key integer dA,
// randomly selected in the interval [1 , n − 1] and a public key curve point QA = dA × G. We use × to denote elliptic curve point multiplication by a scalar.

// For Alice to sign a message m, she follows these steps:
//   1. Calculate e = HASH(m), // HASH is a crypto hash function like SHA2, with the output converted to an int.
//   2. Let z be the leftmost Ln bits of e, where Ln is the bit length of group order n (z can be greater but not longer than n)
//   3. Select a cryptographically secure random int k from [1, n-1]
//   4. Calculate the curve point (x1, y1) = k x G
//   5. Calculate r = x1 mod n. If r == 0, goto step 3
//   6. Calculate s = k-1(z + rda) mod n. If s == 0, goto step 3
//   7. The signature is the pair (r, s). And (r, -s mod n) is also a valid signature


// Signature verification algorithm
// For Bob to authenticate Alice's signature r , s on a message m, he must have a copy of her public-key curve point QA.
// Bob can verify QA is a valid curve point as follows:
//    1. Check that QA is not equal to the identity element O, and its coordinates are otherwise valid.
//    2. Check that QA lies on the curve.
//    3. Check that n × QA = O

// After that, Bob follows these steps:
//    1. Verify that r and s are integers in [1 , n − 1]. If not, the signature is invalid.
//    2. Calculate e = HASH ( m ), where HASH is the same function used in the signature generation.
//    3. Let z be the Ln leftmost bits of e.
//    4. Calculate u1 = z^(s − 1) mod n  and u2 = r^(s − 1) mod n
//    5. Calculate the curve point (x1 , y1) = u1 × G + u2 × QA. If (x1 , y1) = O then the signature is invalid.
//    6. The signature is valid if r ≡ x1 ( mod n ), invalid otherwise.
// Note that an efficient implementation would compute inverse s − 1 mod n only once.
// Also, using Shamir's trick, a sum of two scalar multiplications u1 × G + u2 × QA can be calculated faster than two scalar multiplications done independently
