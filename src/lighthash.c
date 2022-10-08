//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "lightdefs.h"
#include "lighthash.h"

extern u64 SHA_H0[], SHA_K[];
extern u08 masks[], markbit[];

// SHA
void hash_new(const char *in, char* s) {
  char* ra = "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4FC5D"
    "147AC6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1";
  const char hexdigits[] = "0123456789ABCDEF";
  u08* inn = malloc(sizeof(u08)*strlen(in));
  uint8_t msg_dig[sha_hsh_sz];
  shactx sha;
  int j = 0;

  for (unsigned long i = 0; i < strlen(in); i++) inn[i] = (u08)in[i];
  memset(&sha, '\343', sizeof(sha)); // force bad data into struct

  sha_reset((shactx*)&sha);
  sha_input((shactx*)&sha, inn, strlen(in));  
  sha_final((shactx*)&sha, (uint8_t)0, 0);
  sha_result((shactx*)&sha, msg_dig);
  sha_match(msg_dig, ra, 64);

  for (int i = 0; i < 64; ++i) {
    s[j++] = hexdigits[(msg_dig[i] >> 4) & 0xF];
    s[j++] = hexdigits[msg_dig[i] & 0xF];
  }
  s[j]='\0';
  free(inn);
}

//
//
int sha_reset(shactx *c) {
  if (!c) return sha_null;
  c->msg_blk_i = 0;
  c->len_hi = c->len_lo = 0;

  for (int i = 0; i < sha_hsh_sz / 8; i++) c->imh[i] = SHA_H0[i];
  c->compute = 0;
  c->corrupt = sha_ok;
  return sha_ok;
}

//
//
static void sha_proc_msgblk(shactx *c) {
  u64 A, B, C, D, E, F, G, H, W[80], temp1, temp2;
  int t, t8;

  // Initialize the first 16 words in the array W
  for (t = t8 = 0; t < 16; t++, t8 += 8) W[t] =
    ((u64)(c->mb[t8    ]) << 56) |
    ((u64)(c->mb[t8 + 1]) << 48) |
    ((u64)(c->mb[t8 + 2]) << 40) |
    ((u64)(c->mb[t8 + 3]) << 32) |
    ((u64)(c->mb[t8 + 4]) << 24) |
    ((u64)(c->mb[t8 + 5]) << 16) |
    ((u64)(c->mb[t8 + 6]) <<  8) |
    ((u64)(c->mb[t8 + 7]));

  for (t = 16; t < 80; t++)
    W[t] = SHA_s1(W[t-2]) + W[t-7] + SHA_s0(W[t-15]) + W[t-16];
  A = c->imh[0];
  B = c->imh[1];
  C = c->imh[2];
  D = c->imh[3];
  E = c->imh[4];
  F = c->imh[5];
  G = c->imh[6];
  H = c->imh[7];

  for (t = 0; t < 80; t++) {
    temp1 = H + SHA_S1(E) + SHA_Ch(E,F,G) + SHA_K[t] + W[t];
    temp2 = SHA_S0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  c->imh[0] += A;
  c->imh[1] += B;
  c->imh[2] += C;
  c->imh[3] += D;
  c->imh[4] += E;
  c->imh[5] += F;
  c->imh[6] += G;
  c->imh[7] += H;
  c->msg_blk_i = 0;
}

//
//
int sha_input(shactx *c, const u08 *message_array, unsigned int length) {
  uint64_t tmp;

  if (!c) return sha_null;
  if (!length) return sha_ok;
  if (!message_array) return sha_null;
  if (c->compute) return c->corrupt = sha_err;
  if (c->corrupt) return c->corrupt;

  while (length--) {
    c->mb[c->msg_blk_i++] = *message_array;
    if ((SHA_AddLength(c, 8, tmp) == sha_ok) && (c->msg_blk_i == sha_blk_sz))
      sha_proc_msgblk(c);

    message_array++;
  }
  return c->corrupt;
}

//
//
static void sha_pad_msg(shactx *c, u08 pad_byte) {
   // Check to see if the current message block is too small to hold
   // the initial padding bits and length.  If so, we will pad the
   // block, process it, and then continue padding into a second
   // block.
  if (c->msg_blk_i >= (sha_blk_sz - 16)) {
    c->mb[c->msg_blk_i++] = pad_byte;
    while (c->msg_blk_i < sha_blk_sz) c->mb[c->msg_blk_i++] = 0;
    sha_proc_msgblk(c);
  } else c->mb[c->msg_blk_i++] = pad_byte;

  while (c->msg_blk_i < (sha_blk_sz - 16)) c->mb[c->msg_blk_i++] = 0;
  c->mb[112] = (u08)(c->len_hi >> 56);
  c->mb[113] = (u08)(c->len_hi >> 48);
  c->mb[114] = (u08)(c->len_hi >> 40);
  c->mb[115] = (u08)(c->len_hi >> 32);
  c->mb[116] = (u08)(c->len_hi >> 24);
  c->mb[117] = (u08)(c->len_hi >> 16);
  c->mb[118] = (u08)(c->len_hi >> 8);
  c->mb[119] = (u08)(c->len_hi);

  c->mb[120] = (u08)(c->len_lo >> 56);
  c->mb[121] = (u08)(c->len_lo >> 48);
  c->mb[122] = (u08)(c->len_lo >> 40);
  c->mb[123] = (u08)(c->len_lo >> 32);
  c->mb[124] = (u08)(c->len_lo >> 24);
  c->mb[125] = (u08)(c->len_lo >> 16);
  c->mb[126] = (u08)(c->len_lo >> 8);
  c->mb[127] = (u08)(c->len_lo);
  sha_proc_msgblk(c);
}

//
//
static void sha_finalize(shactx *c, u08 pad_byte) {
  sha_pad_msg(c, pad_byte);
  // Clear message
  for (int_least16_t i = 0; i < sha_blk_sz; ++i) c->mb[i] = 0;
  c->len_hi = c->len_lo = 0;
  c->compute = 1;
}

//
//
int sha_final(shactx *c, u08 msg_bit, unsigned int length) {
  uint64_t tmp;

  if (!c) return sha_null;
  if (!length) return sha_ok;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = sha_err;
  if (length >= 8) return c->corrupt = sha_bad;
  SHA_AddLength(c, length, tmp);
  sha_finalize(c, (u08)((msg_bit & masks[length]) | markbit[length]));
  return c->corrupt;
}

//
//
int sha_result(shactx *c, u08 msg_dig[sha_hsh_sz]) {
  if (!c) return sha_null;
  if (!msg_dig) return sha_null;
  if (c->corrupt) return c->corrupt;
  if (!c->compute) sha_finalize(c, 0x80);

  for (int i = 0; i < sha_hsh_sz; ++i)
    msg_dig[i] = (u08)(c->imh[i>>3] >> 8 * (7 - (i % 8)));
  return sha_ok;
}

int sha_match(cuc *hashvalue, cc *hexstr, int hashsize) {
  const char hexdigits[] = "0123456789ABCDEF";

  for (int i = 0; i < hashsize; ++i) {
    if (*hexstr++ != hexdigits[(hashvalue[i] >> 4) & 0xF]) return 0;
    if (*hexstr++ != hexdigits[hashvalue[i] & 0xF]) return 0;
  }
  return 1;
}

void sha_print(uint8_t *md, int hashsize, cc *resultarray) {
  printf("Hash 0x");
  for (int i = 0; i < hashsize * 2; i++) printf("%c", resultarray[i]);
  if (sha_match(md, resultarray, hashsize) == 1)
    printf(" PASSED\n"); else printf(" FAILED\n");
}

int hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs) {
  uint8_t msg_dig[sha_hsh_sz];
  hmacctx hmac;
  shactx sha;
  int err;

  memset(&sha, '\343', sizeof(sha)); // force bad data into struct
  memset(&hmac, '\343', sizeof(hmac));

  if (k) {err = hmac_reset(&hmac, k, kl);}
  else {err = sha_reset((shactx*)&sha);}
  if (err != sha_ok) {return err;}

  for (int i = 0; i < r; ++i) {
    if (k) {err = hmac_input(&hmac, (const uint8_t *)ta, l);}
    else {err = sha_input((shactx*)&sha, (const uint8_t *)ta, l);}
    if (err != sha_ok) {return err;}
  }

  if (neb > 0) {
    if (k) {err = hmac_final(&hmac, (uint8_t)eb, neb);}
    else {err = sha_final((shactx*)&sha, (uint8_t)eb, neb);}
    if (err != sha_ok) {return err;}
  }

  if (k) {err = hmac_result(&hmac, msg_dig);}
  else {err = sha_result((shactx*)&sha, msg_dig);}
  if (err != sha_ok) {return err;}
  // To print the hashes add this below row :
  // sha_print(msg_dig, hs, ra);
  return sha_match(msg_dig, ra, hs);
}

// HMAC

//
// initialize the hmacctx
int hmac_reset(hmacctx *c, cuc *key, int key_len) {
  uc k_ipad[sha_blk_sz], tempkey[sha_hsh_sz];
  int blocksize, hashsize, ret;

  if (!c) return sha_null;
  c->compute = 0;
  c->corrupt = sha_ok;
  blocksize = c->blk_size = sha_blk_sz;
  hashsize = c->size = sha_hsh_sz;

  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    shactx cc;
    int err = sha_reset((shactx*)&cc) ||
      sha_input((shactx*)&cc, key, key_len) ||
      sha_result((shactx*)&cc, tempkey);
    if (err != sha_ok) return err;
    key = tempkey;
    key_len = hashsize;
  }

  // The HMAC transform looks like: SHA(K XOR opad, SHA(K XOR ipad, text))
  // where K is an n byte key, 0-padded to a total of blocksize bytes,
  // ipad is the byte 0x36 repeated blocksize times,
  // opad is the byte 0x5c repeated blocksize times, and text is the data being protected.
  // store key into the pads, XOR'd with ipad and opad values
  for (int i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36; c->k_opad[i] = key[i] ^ 0x5c;
  }

  // remaining pad bytes are '\0' XOR'd with ipad and opad values
  for (int i = key_len; i < blocksize; i++) {
    k_ipad[i] = 0x36; c->k_opad[i] = 0x5c;
  }

  ret = sha_reset((shactx*)&c->shactx) ||
    sha_input((shactx*)&c->shactx, k_ipad, blocksize);
  return c->corrupt = ret;
}

//
//
int hmac_input(hmacctx *c, cuc *text, int text_len) {
  if (!c) return sha_null;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = sha_err;
  return c->corrupt = sha_input((shactx*)&c->shactx, text, text_len);
}

//
// Add final bits
int hmac_final(hmacctx *c, uint8_t bits, unsigned int bit_count) {
  if (!c) return sha_null;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = sha_err;
  return c->corrupt = sha_final((shactx*)&c->shactx, bits,bit_count);
}

//
// Get the hmac digest
int hmac_result(hmacctx *c, uint8_t *digest) {
  if (!c) return sha_null;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = sha_err;

  // finish up 1st pass
  // perform outer SHA, init context for 2nd pass
  // start with outer pad
  // then results of 1st hash
  // finish up 2nd pass
  int ret = sha_result((shactx*)&c->shactx, digest) ||
    sha_reset((shactx*)&c->shactx) ||
    sha_input((shactx*)&c->shactx, c->k_opad, c->blk_size) ||
    sha_input((shactx*)&c->shactx, digest, c->size) ||
    sha_result((shactx*)&c->shactx, digest);
  c->compute = 1;
  return c->corrupt = ret;
}
