//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1
#include "lightdefs.h"

extern const uint8_t K[32],SBOX[16][16],SBOXINV[16][16], GF[15][256], MIX[4][4];
extern const uint64_t WW[8];

void lpencrypt(uint8_t in[], uint32_t l, uint8_t k[], uint8_t *iv,
  uint8_t o[], bool cbc);
void lpdecrypt(uint8_t in[], uint32_t l, uint8_t k[], uint8_t *iv,
  uint8_t o[], bool cbc);
#endif
