// ECDSA
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// https://www.rfc-editor.org/rfc/rfc6979
// https://www.rfc-editor.org/rfc/rfc4050

// https://github.com/smurfd/lightecdh ?


// http://www.secg.org/sec2-v2.pdf
// http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
// https://www.ietf.org/rfc/rfc4492.txt

// https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
// https://www.ietf.org/rfc/rfc4492.txt

// secp521r1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "lightdefs.h"
#include "lightkeys_defs.h"

//
// Imitate pythons %. -1 % 5 = 4, not -1
static int mod(int n, int m) {return ((n % m) + m) % m;}

//
// Copy bits
void lightkeys_bit_copy(bit *x, const bit y, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {(*x)[i] = y[i];}
}

//
// Return the number of the highest one-bit + 1
int lightkeys_bit_degree(const bit x, cur* cc) {
  int i = (*cc).NWOR * 32;
  // Start at the back of the vector (MSB)
  x += (*cc).NWOR;

  // Skip empty / zero words
  while ((i > 0) && (*(--x)) == 0) {i -= 32;}
  // Run through rest if count is not multiple of bitsize of DTYPE
  if (i != 0) {
    u64 u64mask = ((u64)1 << 31);
    while ((u64)((*x) & u64mask) == 0) {
      u64mask >>= 1;
      i -= 1;
    }
  }
  return i;
}

int lightkeys_bit_equal(const bit x, const bit y, cur* cc) {
  int ret = 1;
  for (int i = 0; i < (*cc).NWOR; ++i) {
    ret &= (x[i] == y[i]);
  }
  return ret;
}

//
// Clear bit
void lightkeys_bit_clear(bit x, const u64 idx) {
  x[idx / 32U] &= ~(1U << (idx & 31U));
}

// increment element
void lightkeys_bit_inc(bit x) {x[0] ^= 1;}

//
// Set bits to zero
void lightkeys_bit_zero(bit x, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {x[i] = 0;}
}

//
// Check if bit is zero
int lightkeys_bit_is_zero(const bit x, cur* cc) {
  int ret = 1;
  for (int i = 0; i < (*cc).NWOR; ++i) {
    ret &= (x[i] == 0);
  }
  return ret;
}

void lightkeys_bit_one(bit x, cur* cc) {
  // Set first word to one
  x[0] = 1;
  // .. and the rest to zero
  for (int i = 1; i < (*cc).NWOR; ++i) {
    x[i] = 0;
  }
}

// constant-time check
int lightkeys_bit_is_one(const bit x, cur* cc) {
  int ret = 0;
  // Check if first word == 1
  if (x[0] == 1) {
    ret = 1;
  }
  // ...and if rest of words == 0
  for (int i = 1; i < (*cc).NWOR; ++i) {
    ret &= (x[i] == 0);
  }
  return ret;
}

// left-shift by 'count' digits
void lightkeys_bit_lshift(bit x, const bit y, int nb, cur* cc) {
  int i, j;
  int nw = (nb / 32);

  // Shift whole words first if nwords > 0
  for (i = 0; i < nw; ++i) {
    // Zero-initialize from least-significant word until offset reached
    x[i] = 0;
  }
  j=0;
  // Copy to x output
  while (i < (*cc).NWOR) {
    x[i] = y[j];
    i += 1;
    j += 1;
  }

  // Shift the rest if count was not multiple of bitsize of DTYPE
  nb &= 31;
  if (nb != 0) {
    // Left shift rest
    for (int i = ((*cc).NWOR - 1); i > 0; --i) {
      x[i]  = (x[i] << nb) | (x[i - 1] >> (32 - nb));
    }
    x[0] <<= nb;
  }
}

//
// galois field(2^m) addition is modulo 2, so XOR is used instead - 'z := a + b'
void lightkeys_bit_add(bit z, const bit x, const bit y, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {z[i] = (x[i] ^ y[i]);}
}

int lightkeys_bit_get(const bit x, const u64 idx) {
  return ((x[idx / 32U] >> (idx & 31U) & 1U));
}


void lightkeys_bit_swap(bit *x, bit *y, cur* cc) {
  bit tmp;
  lightkeys_bit_copy(&tmp, (*x), cc);
  lightkeys_bit_copy(&(*x), (*y), cc);
  lightkeys_bit_copy(&(*y), tmp, cc);
}

//
// field multiplication 'z := (x * y)'
void lightkeys_bit_mul(bit *z, const bit x, const bit y, cur* cc) {
  bit tmp;
  assert((*z) != y);

  lightkeys_bit_copy(&tmp, x, cc);

  // LSB set? Then start with x
  if (lightkeys_bit_get(y, 0) != 0) {
    lightkeys_bit_copy(&(*z), x, cc);
  } else {
    lightkeys_bit_zero((*z), cc);
  }

  // Then add 2^i * x for the rest
  for (int i = 1; i < (*cc).DEGR; ++i) {
    //extern bit ecdh_p;
    // lshift 1 - doubling the value of tmp
    lightkeys_bit_lshift(tmp, tmp, 1, cc);

    // Modulo reduction polynomial if degree(tmp) > CURVE_DEGREE
    if (lightkeys_bit_get(tmp, (*cc).DEGR)) {
      lightkeys_bit_add(tmp, tmp, (*cc).ecdh_p, cc);
    }

    // Add 2^i * tmp if this factor in y is non-zero
    if (lightkeys_bit_get(y, i)) {lightkeys_bit_add((*z), (*z), tmp, cc);}
  }
}

// field inversion 'z := 1/x'
void lightkeys_bit_inv(bit *z, const bit x, cur* cc) {
  bit u, v, g, h;

  lightkeys_bit_copy(&u, x, cc);
  lightkeys_bit_copy(&v, (*cc).ecdh_p, cc);
  lightkeys_bit_zero(g, cc);
  lightkeys_bit_one((*z), cc);

  while (!lightkeys_bit_is_one(u, cc)) {
    int i = (lightkeys_bit_degree(u, cc) - lightkeys_bit_degree(v, cc));
    if (i < 0) {
      lightkeys_bit_swap(&u, &v, cc);
      lightkeys_bit_swap(&g, &(*z), cc);
      i = -i;
    }
    lightkeys_bit_lshift(h, v, i, cc);
    lightkeys_bit_add(u, u, h, cc);
    lightkeys_bit_lshift(h, g, i, cc);
    lightkeys_bit_add((*z), (*z), h, cc);
  }
}

//
// Set point to Zero
void lightkeys_point_zero(pt *p1, cur* cc) {
  lightkeys_bit_zero((*p1).x, cc);
  lightkeys_bit_zero((*p1).y, cc);
}

int lightkeys_point_is_zero(const pt p1, cur* cc) {
  return (lightkeys_bit_is_zero(p1.x, cc) && lightkeys_bit_is_zero(p1.y, cc));
}

//
// Copy point
void lightkeys_point_copy(pt *p1, const pt p2, cur* cc) {
  lightkeys_bit_copy(&(*p1).x, p2.x, cc);
  lightkeys_bit_copy(&(*p1).y, p2.y, cc);
}

// double the point (x,y)
void lightkeys_point_double(pt *p1, cur* cc) {
  // if P = O (zero or infinity): 2 * P = P
  if (lightkeys_point_is_zero((*p1), cc)) {
    lightkeys_point_zero(&(*p1), cc);
  } else {
    bit l;
    //extern int ecdh_a;
    lightkeys_bit_inv(&l, (*p1).x, cc);
    lightkeys_bit_mul(&l, l, (*p1).y, cc);
    lightkeys_bit_add(l, l, (*p1).x, cc);
    lightkeys_bit_mul(&(*p1).y, (*p1).x, (*p1).x, cc);
    lightkeys_bit_mul(&(*p1).x, l, l, cc);
    if ((*cc).ecdh_a == 1) {lightkeys_bit_inc(l);}
    lightkeys_bit_add((*p1).x, (*p1).x, l, cc);
    lightkeys_bit_mul(&l, l, (*p1).x, cc);
    lightkeys_bit_add((*p1).y, (*p1).y, l, cc);
  }
}

//
// add two points together (x1, y1) := (x1, y1) + (x2, y2)
void lightkeys_point_add(pt *p1, pt p2, const pt p3, cur* cc) {
  //extern int ecdh_a;
  if (!lightkeys_point_is_zero(p3, cc)) {
    if (lightkeys_point_is_zero(p2, cc)) {
      lightkeys_point_copy(&p2, p3, cc);
    } else {
      if (lightkeys_bit_equal(p2.x, p3.x, cc)) {
        if (lightkeys_bit_equal(p2.y, p3.y, cc)) {
          lightkeys_point_double(&p2, cc);
        } else {
          lightkeys_point_zero(&p2, cc);
        }
      } else {
        // Arithmetic with temporary variables
        bit a, b, c, d;

        lightkeys_bit_add(a, p2.y, p3.y, cc);
        lightkeys_bit_add(b, p2.x, p3.x, cc);
        lightkeys_bit_inv(&c, b, cc);
        lightkeys_bit_mul(&c, c, a, cc);
        lightkeys_bit_mul(&d, c, c, cc);
        lightkeys_bit_add(d, d, c, cc);
        lightkeys_bit_add(d, d, b, cc);
        if ((*cc).ecdh_a == 1) {lightkeys_bit_inc(d);}
        lightkeys_bit_add(p2.x, p2.x, d, cc);
        lightkeys_bit_mul(&a, p2.x, c, cc);
        lightkeys_bit_add(a, a, d, cc);
        lightkeys_bit_add(p2.y, p2.y, a, cc);
        lightkeys_bit_copy(&p2.x, d, cc);
      }
    }
  }
}

//
// Multiply points
void lightkeys_point_mul(pt *p1, const pt p2, bit exp, cur* cc) {
  bit tmpx, tmpy, dummyx, dummyy;
  int nb = lightkeys_bit_degree(exp, cc);
  pt tmp, dummy;

  lightkeys_point_zero(&tmp, cc);
  lightkeys_point_zero(&dummy, cc);
  for (int i = (nb - 1); i >= 0; --i) {
    lightkeys_point_double(&tmp, cc);
    // Add point if bit(i) is set in exp
    if (lightkeys_bit_get(exp, i)) {
      lightkeys_point_add(&tmp, tmp, p2, cc);
    }
  }
  lightkeys_point_copy(p1, tmp, cc);
}

//
// Print bits
void lightkeys_print_bit(bit a, cur* cc) {
  printf("[ ");
  for (int i = 0; i < (*cc).NWOR; ++i) {
    printf("0x%.8llx ", (u64)a[i]);
  }
  printf("]\n");
}

//
// Init curve
void lightkeys_curves_init(cur* cc) {
  memcpy((*cc).ecdh_p, ecdh_p, sizeof(bit));
  memcpy((*cc).ecdh_b, ecdh_b, sizeof(bit));
  memcpy((*cc).ecdh_x, ecdh_x, sizeof(bit));
  memcpy((*cc).ecdh_y, ecdh_y, sizeof(bit));
  memcpy((*cc).ecdh_n, ecdh_n, sizeof(bit));
  (*cc).ecdh_a = ecdh_a;
  (*cc).ecdh_h = ecdh_h;
  (*cc).DEGR = ecdh_DEGR;
  (*cc).PRIV = ecdh_PRIV;

  (*cc).PUBL = (*cc).PRIV * 2;
  (*cc).MARG = 3;
  (*cc).NBIT = ((*cc).DEGR + (*cc).MARG);
  (*cc).NWOR = (((*cc).NBIT + 31) / 32);
  (*cc).NBYT = (sizeof(u64) + (*cc).NWOR);
}

//
// End / Free curve
void lightkeys_curves_end(cur* cc) {free(cc);}

// Generate keypair
void lightkeys_keygen(u64* pubkey, u64* privkey, cur* cc) {
  for (u64 i = 0; i < (u64)(*cc).PUBL; ++i) {pubkey[i] = 0;}
  pt *p = malloc(sizeof(pt)), *p2 = malloc(sizeof(pt));
  memcpy((*p).x, (*cc).ecdh_x, sizeof(bit));
  memcpy((*p).y, (*cc).ecdh_y, sizeof(bit));

  //lightkeys_point_copy((u64*)(pubkey), (u64*)(pubkey + (*cc).NBYT), (*cc).ecdh_x, (*cc).ecdh_y, cc);
  lightkeys_point_copy(&(*p2), (*p), cc);

  int nb = lightkeys_bit_degree((*cc).ecdh_n, cc);
  for (int i = (nb - 1); i < ((((*cc).DEGR + 3 + 31) / 32) * 32); ++i) {
    lightkeys_bit_clear(privkey, i);
  }
  memcpy((*p2).x, privkey, (*cc).PRIV);
  lightkeys_point_mul(&(*p2), (*p2), privkey, cc);
  free(p);
  free(p2);
}
