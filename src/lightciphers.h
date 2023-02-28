//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1
#include "lightdefs.h"

extern const uint8_t K[32],SBOX[16][16],SBOXINV[16][16], GF[15][256], MIX[4][4];
extern const uint64_t WW[8];

void lciphers_encrypt(uint8_t in[], uint32_t l, uint8_t k[], uint8_t *iv,
  uint8_t o[], bool cbc);
void lciphers_decrypt(uint8_t in[], uint32_t l, uint8_t k[], uint8_t *iv,
  uint8_t o[], bool cbc);
#endif
