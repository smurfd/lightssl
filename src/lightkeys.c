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
#include "lightdefs.h"
#include "lightkeys_defs.h"

//
// Imitate pythons %. -1 % 5 = 4, not -1
static int mod(int n, int m) {return ((n % m) + m) % m;}

//
// Copy bits
void lightecdh_bit_copy(bit *x, const bit y, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {
    (*x)[i] = y[i];
  }
}

//
// Copy point
void lightecdh_point_copy(pt *p1, const pt p2, cur* cc) {
  lightecdh_bit_copy(&(*p1).x, p2.x, cc);
  lightecdh_bit_copy(&(*p1).y, p2.y, cc);
}

//
// Print bits
void print_bit(bit a, cur* cc) {
  printf("[ ");
  for (int i = 0; i < (*cc).NWOR; ++i) {
    printf("0x%.8llx ", (u64)a[i]);
  }
  printf("]\n");
}

//
// Init curve
void lightecdh_curves_init(cur* cc) {
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
void lightecdh_curves_end(cur* cc) {
  free(cc);
}
