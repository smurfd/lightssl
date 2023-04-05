//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1
#include "lightdefs.h"

extern const uint8_t SBOXINV[16][16], GF[15][256], MIX[4][4], MIX[4][4];
extern const uint8_t K[32], SBOX[16][16];
extern const u64 WW[8];

void ciph_encrypt(uint8_t in[], uint8_t k[], uint8_t *iv, uint8_t o[], bool cbc);
void ciph_decrypt(uint8_t in[], uint8_t k[], uint8_t *iv, uint8_t o[], bool cbc);
#endif
