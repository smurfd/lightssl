// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef KEYS_H
#define KEYS_H 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
//#include "definitions.h"
#define BLOCK 1024
#define LEN 4096
#define BYTES 48
#define DIGITS (BYTES / 8)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define EVEN(p) (!(p[0] & 1))
// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m
typedef struct pt {u64 x[DIGITS], y[DIGITS];} pt;
typedef struct prng_t {u64 a, b, c, d;} prng_t;
__extension__ typedef unsigned __int128 uint128;
u64 keys_write(char *fn, uint8_t data[], int type);
int keys_make(uint8_t publ[], uint8_t priv[]);
int keys_secr(const uint8_t pub[], const uint8_t prv[], uint8_t scr[]);
int keys_sign(const uint8_t priv[], uint8_t hash[], uint8_t sign[]);
int keys_vrfy(const uint8_t publ[], const uint8_t hash[], const uint8_t sign[]);
int base64enc(char ed[], const uint8_t *data, int inl);
int base64dec(uint8_t dd[], const char *data, int inl);
#endif
