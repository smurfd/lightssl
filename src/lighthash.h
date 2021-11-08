//                                                                            //
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1

#define BYTE 8
#define SHA512_BLOCK_SIZE 1024/BYTE
#define DIGEST_SIZE 512/BYTE

char* lh_new(const char* in);
void lh_init();
void lh_update(const unsigned char *msg, uint8_t len);
void lh_finalize(unsigned char *digest);
void lh_transform(const unsigned char *msg, uint8_t blocknb);
bool lh_verify(const char *hash, const char *ver_hash);

uint8_t m_tot_len;
uint8_t m_len;
unsigned char m_block[2 * SHA512_BLOCK_SIZE];
uint64_t m_h[8];

#endif
