//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1

#include "defs.h"

#define NB 4
#define NK 8
#define NR 14
#define NB4 NB * 4
#define NK4 NK * 4
#define NBR1 NB * (NR + 1)
#define BBL 4 * NB * sizeof(unsigned char)

extern const u64 WW[8];
extern const u08 K[32];
extern const u08 SBOX[16][16];
extern const u08 SBOXINV[16][16];
extern const u08 GF[15][256];
extern const u08 MIX[4][4];
extern const u08 MIX[4][4];

void lightciphers_encrypt(u08 in[], ui l, u08 k[], u08 *iv, u08 o[], bool cbc);
void lightciphers_decrypt(u08 in[], ui l, u08 k[], u08 *iv, u08 o[], bool cbc);
#endif
