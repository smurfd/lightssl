//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1
#include "lightdefs.h"

extern const u64 WW[8];
extern const u08 K[32];
extern const u08 SBOX[16][16];
extern const u08 SBOXINV[16][16];
extern const u08 GF[15][256];
extern const u08 MIX[4][4];
extern const u08 MIX[4][4];

void lciphers_encrypt(u08 in[], ui l, u08 k[], u08 *iv, u08 o[], bool cbc);
void lciphers_decrypt(u08 in[], ui l, u08 k[], u08 *iv, u08 o[], bool cbc);
#endif
