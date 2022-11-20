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

static void copy_state(u08 s[4][NB], u08 in[4][NB]) {
  //int count = 0;

  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < NB; ++i) {
      s[j][i] = in[j][i];
      //count++;
    }
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
  if (state[0][0] || w[0][0]) {}
}

// 5.1.x
static void lightciphers_subbytes(u08 state[4][NB]) {// See Sec. 5.1.1
  if (state[0][0]) {}
}

static void lightciphers_shiftrows(u08 state[4][NB]) {// See Sec. 5.1.2
  if (state[0][0]) {}
}

static void lightciphers_mixcolumns(u08 state[4][NB]) {// See Sec. 5.1.3
  if (state[0][0]) {}
}

static void lightciphers_cipher(u08 in[4][NB], u08 out[4][NB], u64 w[NR][NB]) {
  u08 state[4][NB];

  copy_state(state, in);
  lightciphers_addroundkey(state, w);//[0][NB-1]); //w[0, Nb-1]
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
