// Auth: smurfd, 2024 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#ifndef AES_H
#define AES_H 1
#include <stdint.h>
#define KEYSIZE1 sizeof(uint32_t) * 4
#define KEYSIZE2 sizeof(uint32_t) * 8
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define MAXPLAIN 68719476704 // (2 ^ 39) - 256
#define MAXAAD 2305843009213693952 // (2 ^ 64) - 1
#define MAXIV 2305843009213693952 // (2 ^ 64) - 1
// AES
void cipher(uint32_t *ret, const uint32_t *key, const uint32_t *block);
void inv_cipher(uint32_t *ret, const uint32_t *key, const uint32_t *block);
// AES GCM
void gcm_ciphertag(uint8_t *c, uint8_t *t, const uint8_t *key, uint8_t *iv, const uint8_t *plain, const uint8_t *aad, const u64 lenx);
void gcm_inv_ciphertag(uint8_t *plain, uint8_t *t, const uint8_t *key, const uint8_t *iv, const uint8_t *c, const uint8_t *aad, const uint8_t *tag);
// AES GCM 32bit
void gcm_ciphertag32bit(uint32_t *c, uint32_t *t, const uint32_t *key, uint32_t *iv, const uint32_t *plain, const uint32_t *aad, const u64 lenx);
void gcm_inv_ciphertag32bit(uint32_t *plain, uint32_t *t, const uint32_t *key, const uint32_t *iv, const uint32_t *c, const uint32_t *aad, const uint32_t *tag);
#endif
// Code grabbed from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf and massaged
