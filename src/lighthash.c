//                                                                            //
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lighthash.h"
#include "defs.h"

extern uint64_t sha[80];
extern uint64_t sha_init[8];

// "Construct"
char* lighthash_new(const char* in) {
  unsigned char digest[DIGEST_SIZE];
  char* buf;
  memset(digest,0,DIGEST_SIZE);
  buf = (char*) malloc(2 * DIGEST_SIZE + 1);
  buf[2 * DIGEST_SIZE] = 0;

  lighthash_init();
  lighthash_update((unsigned char*)in, strlen(in));
  lighthash_finalize(digest);

  for (int i = 0; i < DIGEST_SIZE; i++) {
    sprintf(buf+i*2, "%02x", digest[i]);
  }
  return buf;
}

// Initialize
void lighthash_init() {
  for (int i=0; i<8; i++) {
    m_h[i] = sha_init[i];
  }
  m_len = 0;
  m_tot_len = 0;
}

// Update
void lighthash_update(const unsigned char *msg, uint8_t len) {
  uint8_t block_nb;
  uint8_t new_len, rem_len, tmp_len;
  const unsigned char *shifted_message;
  tmp_len = SHA512_BLOCK_SIZE - m_len;
  rem_len = len < tmp_len ? len : tmp_len;
  memcpy(&m_block[m_len], msg, rem_len);

  if (m_len + len < SHA512_BLOCK_SIZE) {
    m_len += len;
    return;
  }
  new_len = len - rem_len;
  block_nb = new_len / SHA512_BLOCK_SIZE;
  shifted_message = msg + rem_len;
  lighthash_transform(m_block, 1);
  lighthash_transform(shifted_message, block_nb);
  rem_len = new_len % SHA512_BLOCK_SIZE;
  memcpy(m_block, &shifted_message[block_nb << 7], rem_len);
  m_len = rem_len;
  m_tot_len += (block_nb + 1) << 7;
}

// Finalize
void lighthash_finalize(unsigned char *digest) {
  uint8_t block_nb;
  uint8_t pm_len;
  uint8_t len_b;
  block_nb = 1 + ((SHA512_BLOCK_SIZE - 17) < (m_len % SHA512_BLOCK_SIZE));
  len_b = (m_tot_len + m_len) << 3;
  pm_len = block_nb << 7;
  memset(m_block + m_len, 0, pm_len - m_len);
  m_block[m_len] = 0x80;
  SHA2_UNPACK32(len_b, m_block + pm_len - 4);
  lighthash_transform(m_block, block_nb);

  for (int i = 0 ; i < 8; i++) {
    SHA2_UNPACK64(m_h[i], &digest[i << 3]);
  }
}

// Transform
void lighthash_transform(const unsigned char *msg, uint8_t blocknb) {
  uint64_t w[80];
  uint64_t wv[8];
  uint64_t t1, t2;
  const unsigned char *sub_block;
  for (int i = 0; i < (int) blocknb; i++) {
    sub_block = msg + (i << 7);
    for (int j = 0; j < 16; j++) {
      SHA2_PACK64(&sub_block[j << 3], &w[j]);
    }
    for (int j = 16; j < 80; j++) {
      w[j] = SHA512_F4(w[j -  2]) + w[j -  7] + SHA512_F3(w[j - 15]) + w[j - 16];
    }
    for (int j = 0; j < 8; j++) {
      wv[j] = m_h[j];
    }
    for (int j = 0; j < 80; j++) {
      t1 = wv[7] + SHA512_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha[j] + w[j];
      t2 = SHA512_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
      wv[7] = wv[6];
      wv[6] = wv[5];
      wv[5] = wv[4];
      wv[4] = wv[3] + t1;
      wv[3] = wv[2];
      wv[2] = wv[1];
      wv[1] = wv[0];
      wv[0] = t1 + t2;
    }
    for (int j = 0; j < 8; j++) {
       m_h[j] += wv[j];
    }
  }
}

bool lighthash_verify(const char *hash, const char *ver_hash) {
  if (strcasecmp(hash, ver_hash) == 0) {
    return true;
  } else {
    return false;
  }
}
