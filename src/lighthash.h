//                                                                            //
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "defs.h"

#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1

char* lighthash_new(const char* in);
void lighthash_init();
void lighthash_update(const unsigned char *msg, u08 len);
void lighthash_finalize(unsigned char *digest);
void lighthash_transform(const unsigned char *msg, u08 blocknb);
bool lighthash_verify(const char *hash, const char *ver_hash);

u08 m_tot_len;
u08 m_len;
unsigned char m_block[2 * SHA512_BLOCK_SIZE];
u64 m_h[8];

#endif
