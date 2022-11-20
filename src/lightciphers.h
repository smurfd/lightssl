//                                                                            //
#ifndef LIGHTCIPHERS_H
#define LIGHTCIPHERS_H 1

#define NB 4
#define NK 8
#define NR 14
#define NB4 NB * 4
#define NK4 NK * 4
#define NBR1 NB*(NR+1)
#define MOD(n, m) ((n % m)+m) % m

extern const u64 WW[8];
extern const u08 K[32];
extern const u08 SBOX[16][16];

void lightciphers_cip();

#endif
