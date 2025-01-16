// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1
#include "lightdefs.h"

extern const uint8_t SBOXINV[16][16], GF[15][256], MIX[4][4], MIX[4][4], K[32], SBOX[16][16];
extern const u64 WW[8];

void ciph_crypt(uint8_t out[], const uint8_t in[], const uint8_t k[], const uint8_t *iv, const bool cbc, bool dec);
#endif
