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
/*
Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
begin
  byte state[4,Nb]
  state = in
  AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
  for round = 1 step 1 to Nr–1
    SubBytes(state) // See Sec. 5.1.1
    ShiftRows(state) // See Sec. 5.1.2
    MixColumns(state) // See Sec. 5.1.3
    AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
  end for
  SubBytes(state)
  ShiftRows(state)
  AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
  out = state
end

KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
begin
  word temp
  i = 0
  while (i < Nk)
    w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
    i = i+1
  end while
  i = Nk
  while (i < Nb * (Nr+1)]
    temp = w[i-1]
    if (i mod Nk = 0)
      temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
    else if (Nk > 6 and i mod Nk = 4)
      temp = SubWord(temp)
    end if
    w[i] = w[i-Nk] xor temp
    i = i + 1
  end while
end

InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
begin
  byte state[4,Nb]
  state = in
  AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
  for round = Nr-1 step -1 downto 1
    InvShiftRows(state) // See Sec. 5.3.1
    InvSubBytes(state) // See Sec. 5.3.2
    AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
    InvMixColumns(state) // See Sec. 5.3.3
  end for
  InvShiftRows(state)
  InvSubBytes(state)
  AddRoundKey(state, w[0, Nb-1])
  out = state
end


EqInvCipher(byte in[4*Nb], byte out[4*Nb], word dw[Nb*(Nr+1)])
begin
  byte state[4,Nb]
  state = in
  AddRoundKey(state, dw[Nr*Nb, (Nr+1)*Nb-1])
  for round = Nr-1 step -1 downto 1
    InvSubBytes(state)
    InvShiftRows(state)
    InvMixColumns(state)
    AddRoundKey(state, dw[round*Nb, (round+1)*Nb-1])
  end for
  InvSubBytes(state)
  InvShiftRows(state)
  AddRoundKey(state, dw[0, Nb-1])
  out = state
end

For the Equivalent Inverse Cipher, the following pseudo code is added at
the end of the Key Expansion routine (Sec. 5.2):

for i = 0 step 1 to (Nr+1)*Nb-1
  dw[i] = w[i]
end for
for round = 1 step 1 to Nr-1
  InvMixColumns(dw[round*Nb, (round+1)*Nb-1]) // note change of type
end for

Note that, since InvMixColumns operates on a two-dimensional array of bytes
while the Round Keys are held in an array of words, the call to
InvMixColumns in this code sequence involves a change of type (i.e. the
input to InvMixColumns() is normally the State array, which is considered
to be a two-dimensional array of bytes, whereas the input here is a Round
Key computed as a one-dimensional array of words).
*/

#include <math.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "lightciphers.h"

// 5.3.x
static void lightciphers_invshiftrows(u64 *state) {// See Sec. 5.3.1

}

static void lightciphers_invsubbytes(u64 *state) {// See Sec. 5.3.2

}

static void InvMixColumns(u64 *state) {// See Sec. 5.3.3

}

static void lightciphers_addroundkey(u64 *state, w[0, NB-1]) {// See Sec. 5.1.4

}

// 5.1.x
static void lightciphers_subbytes(u64 *state) {// See Sec. 5.1.1

}

static void lightciphers_shiftrows(u64 *state) {// See Sec. 5.1.2

}

static void lightciphers_mixcolumns(u64 *state) {// See Sec. 5.1.3

}

static void lightciphers_cipher(b08 in[NB4], b08 out[NB4], u64 w[NBR1]) {

}

static void lightciphers_keyexpansion(b08 key[NK4], u64 w[NBR1], b08 NK) {

}

static void lightciphers_invcipher(b08 in[NB4], b08 out[NB4], u64 w[NBR1]) {

}

static void lightciphers_eqinvcipher(b08 in[NB4], b08 out[NB4], u64 dw[NBR1]) {

}
