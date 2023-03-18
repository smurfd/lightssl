//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1
#include "lightdefs.h"

extern const u64 WW[8];
extern const uint8_t K[32];
extern const uint8_t SBOX[16][16];
extern const uint8_t SBOXINV[16][16];
extern const uint8_t GF[15][256];
extern const uint8_t MIX[4][4];
extern const uint8_t MIX[4][4];

void lciphers_encrypt(uint8_t in[], uint32_t l, uint8_t k[], uint8_t *iv, uint8_t o[], bool cbc);
void lciphers_decrypt(uint8_t in[], uint32_t l, uint8_t k[], uint8_t *iv, uint8_t o[], bool cbc);
#endif
