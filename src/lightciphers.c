// AES
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
// https://www.rfc-editor.org/rfc/rfc3565
// https://www.rfc-editor.org/rfc/rfc3565
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

// Cipher Key = 60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81
// 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4
// Nk = 8
// w0 = 603deb10 w1 = 15ca71be w2 = 2b73aef0 w3 = 857d7781
// w4 = 1f352c07 w5 = 3b6108d7 w6 = 2d9810a3 w7 = 0914dff4
// C.3 AES-256 (Nk=8, Nr=14)
// PLAINTEXT: 00112233445566778899aabbccddeeff
// KEY: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

// Pseudodcode from fips 197
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "lightdefs.h"
#include "lightciphers.h"

const u64 WW[8] = {
  0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
  0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
const u08 K[32] = {
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
const u08 SBOX[16][16] = {
  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

static void copy_state(u08 s[4][NB], u08 in[4][NB]) {
  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < NB; ++i) {s[j][i] = in[j][i];}
  }
}

static void multiply_state(int m1, int m2, u08 mat1[m1][m2], int n1, int n2, u08 mat2[n1][n2], u08 state[4][NB]) {
  int x, i, j;
  int res[m1][n2];
  for (i = 0; i < m1; i++) {
    for (j = 0; j < n2; j++) {
      res[i][j] = 0;
      for (x = 0; x < m2; x++) {
        *(*(res + i) + j) += *(*(mat1 + i) + x) * *(*(mat2 + x) + j);
      }
    }
  }
  for (i = 0; i < m1; i++) {
    for (j = 0; j < n2; j++) {state[i][j] = *(*(res + i) + j);}
  }
}

// 5.3.x
static void lightciphers_invshiftrows(u08 state[4][NB]) {// See Sec. 5.3.1
  if (state[0][0]) {}
}

static void lightciphers_invsubbytes(u08 state[4][NB]) {// See Sec. 5.3.2
  if (state[0][0]) {}
}

static void lightciphers_invmixcolumns(u08 state[4][NB]) {// See Sec. 5.3.3
  if (state[0][0]) {}
}

static void lightciphers_addroundkey(u08 state[4][NB], u64 w[4][NB]) {// See Sec. 5.1.4
  u08 tmp[4][NB];

  copy_state(tmp, state);
  for (int j = 0; j < NB; ++j) {
    for (int i = 0; i < 4; ++i) {
      tmp[i][j] = state[i][j] ^ w[i][j];
    }
  }
  copy_state(state, tmp);
}

// 5.1.x
static void lightciphers_subbytes(u08 state[4][NB]) {// See Sec. 5.1.1
  if (state[0][0]) {}
}

static void lightciphers_shiftrows(u08 state[4][NB]) {// See Sec. 5.1.2
  u08 tmp[4][NB];

  copy_state(tmp, state);
  for (int j = 1; j < 4; ++j) {
    int k = NB - j;
    for (int i = 0; i < NB; ++i) {
      tmp[j][k] = state[j][i];
      if (k > NB) k = 0;
      k++;
    }
  }
  copy_state(state, tmp);
}

static void lightciphers_mixcolumns(u08 state[4][NB]) {// See Sec. 5.1.3
  u08 tmp[4][NB], tmp2[4][NB];

  copy_state(tmp, state);
  for (int j = 0; j < NB; ++j) {
    for (int i = 0; i < 4; ++i) {
      tmp2[i][j] = tmp[i][j];
    }
    multiply_state(4, NB, tmp, 1, NB, tmp2, tmp);
  }
  copy_state(state, tmp);
}

static void lightciphers_cipher(u08 in[4][NB], u08 out[4][NB], u64 w[NR][NB]) {
  u08 state[4][NB];

  copy_state(state, in);
  lightciphers_addroundkey(state, w); //w[0, Nb-1]
  for (int r = 1; r < NR -1; ++r) {
    lightciphers_subbytes(state);
    lightciphers_shiftrows(state);
    lightciphers_mixcolumns(state);
    lightciphers_addroundkey(state, w); //w[r*NB, (r+1)*NB-1]
  }
  lightciphers_subbytes(state);
  lightciphers_shiftrows(state);
  lightciphers_addroundkey(state, w); //w[NR*NB, (NR+1)*NB-1]
  copy_state(out, state);
}

static u64 lightciphers_subword(u64 wrd) {// define?
  return wrd;
}

static u64 lightciphers_rotword(u64 wrd) {// define?
  return wrd;
}

static u64 lightciphers_rcon(u64 wrd) {// define?
  return wrd;
}

static void lightciphers_keyexpansion(u08 key[4][NK], u64 w[NB][NR], u08 n) {
  u64 tmp;

  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < n; ++i) {
      w[j][i] = (u64)(key[j][4*i+0] | key[j][4*i+1]| key[j][4*i+2]| key[j][4*i+3]);
    }
  }
  for (int j = 0; j < 4; ++j) {
    for (int i = n; i < NB * (NR - 1); ++i) {
      tmp = w[j][i];
      if (MOD(i, n) == 0) {
        tmp = lightciphers_subword(lightciphers_rotword(tmp)) ^
          lightciphers_rcon(i/n);
      } else if (n > 6 && MOD(i, n) == 4) {
        tmp = lightciphers_subword(tmp);
      }
      w[j][i] = w[j][i-n] ^ tmp;
    }
  }
}

static void lightciphers_invcipher(u08 in[4][NB], u08 out[4][NB], u64 w[NR][NB]) {
  u08 state[4][NB];

  copy_state(state, in);
  lightciphers_addroundkey(state, w); //w[Nr*Nb, (Nr+1)*Nb-1])
  for (int r = NR - 1; r >= 1; r--) {
    lightciphers_invshiftrows(state);
    lightciphers_invsubbytes(state);
    lightciphers_addroundkey(state, w); //w[round*Nb, (round+1)*Nb-1]
    lightciphers_invmixcolumns(state);
  }
  lightciphers_invshiftrows(state);
  lightciphers_invsubbytes(state);
  lightciphers_addroundkey(state, w); //w[0, Nb-1]
  copy_state(out, state);
}

static void lightciphers_eqinvcipher(u08 in[4][NB], u08 out[4][NB], u64 dw[NR][NB]) {
  u08 state[4][NB];

  copy_state(state, in);
  lightciphers_addroundkey(state, dw); //dw[Nr*Nb, (Nr+1)*Nb-1]
  for (int r = NR - 1; r >= 1; r--) {
    lightciphers_invsubbytes(state);
    lightciphers_invshiftrows(state);
    lightciphers_invmixcolumns(state);
    lightciphers_addroundkey(state, dw); //dw[round*Nb, (round+1)*Nb-1]
  }
  lightciphers_invsubbytes(state);
  lightciphers_invshiftrows(state);
  lightciphers_addroundkey(state, dw); //w[0, Nb-1]
  copy_state(out, state);
}

//
// Just to get rid of warning for not used functions
void lightciphers_cip() {
  u08 in[4][NB], out[4][NB];
  u64 w[4][NB], dw[NR][NB];

  lightciphers_eqinvcipher(in, out, dw);
  lightciphers_invcipher(in, out, w);
  //lightciphers_keyexpansion(in, dw, 0);
  //lightciphers_cipher(in, out, w);
}
