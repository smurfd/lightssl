//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "lightdefs.h"
#include "lighthash.h"
#include "lighthash_testdata.h"

//
// SHA Process message block
static void sha_proc_msgblk(ctxs *c) {
  u64 A[8], W[80], t1, t2, t3 = 0;
  int t, t8;

  // Initialize the first 16 words in the array W
  for (t = t8 = 0; t < 16; t++, t8 += 8) {
    t3 = 0;
    for (int i = 0; i < 8; i++) t3 |= ((u64)(c->mb[t8 + i]) << (56 - (i * 8)));
    W[t] = t3;
  }
  for (t = 16; t < 80; t++) {
    W[t] = SHA_s1(W[t - 2]) + W[t - 7] + SHA_s0(W[t - 15]) + W[t - 16];
  }
  for (int i = 0; i < 8; i++) {A[i] = c->imh[i];}
  for (t = 0; t < 80; t++) {
    t1 = A[7] + SHA_S1(A[4]) + SHA_CH00(A[4],A[5],A[6]) + SHA_K[t] + W[t];
    t2 = SHA_S0(A[0]) + SHA_MAJ0(A[0], A[1], A[2]);
    A[7] = A[6];
    A[6] = A[5];
    A[5] = A[4];
    A[4] = A[3] + t1;
    A[3] = A[2];
    A[2] = A[1];
    A[1] = A[0];
    A[0] = t1 + t2;
  }
  for (int i = 0; i < 8; i++) {c->imh[i] += A[i];}
  c->msg_blk_i = 0;
}

//
// SHA Pad message if needed. Process it. Cont pad 2nd block if needed.
static void sha_pad_msg(ctxs *c, u08 pad_byte) {
  if (c->msg_blk_i >= (sha_blk_sz - 16)) {
    c->mb[c->msg_blk_i++] = pad_byte;
    while (c->msg_blk_i < sha_blk_sz) c->mb[c->msg_blk_i++] = 0;
    sha_proc_msgblk(c);
  } else c->mb[c->msg_blk_i++] = pad_byte;
  while (c->msg_blk_i < (sha_blk_sz - 16)) {c->mb[c->msg_blk_i++] = 0;}
  for (int i = 0; i < 8; i++) c->mb[112 + i] = (u08)(c->len_hi >> (56 - (i*8)));
  for (int i = 0; i < 8; i++) c->mb[120 + i] = (u08)(c->len_lo >> (56 - (i*8)));
  sha_proc_msgblk(c);
}

//
// SHA Finalize
static void sha_finalize(ctxs *c, u08 pad_byte) {
  sha_pad_msg(c, pad_byte);
  // Clear message
  for (int_least16_t i = 0; i < sha_blk_sz; ++i) {c->mb[i] = 0;}
  c->len_hi = c->len_lo = 0;
  c->compute = 1;
}

//
// SHA Error check
static int sha_error(ctxs *c, cu8 *msg_arr, ui length, int b) {
  if (!c) return sha_null;
  if (!length) return sha_ok;
  if (!msg_arr && b == 0) return sha_null;
  if (c->compute) return c->corrupt = sha_err;
  if (c->corrupt) return c->corrupt;
  if (length >= 8 && b == 1) return c->corrupt = sha_bad;
  return sha_ok;
}

//
// SHA Clear
static int sha_reset(ctxs *c) {
  if (!c) return sha_null;
  c->msg_blk_i = 0;
  c->len_hi = c->len_lo = 0;
  c->compute = 0;
  c->corrupt = sha_ok;
  for (int i = 0; i < sha_hsh_sz / 8; i++) {c->imh[i] = SHA_H0[i];}
  return sha_ok;
}

//
// SHA Input
static int sha_input(ctxs *c, cu8 *msg_arr, ui length) {
  sha_error(c, msg_arr, length, 0);
  while (length--) {
    c->mb[c->msg_blk_i++] = *msg_arr;
    if ((SHA_AddLength(c, 8) == sha_ok) && (c->msg_blk_i == sha_blk_sz))
      sha_proc_msgblk(c);
    msg_arr++;
  }
  return c->corrupt;
}

//
// SHA Add final bits
static int sha_final(ctxs *c, u08 msg_bit, ui length) {
  sha_error(c, (cu8 *)0, length, 1);
  SHA_AddLength(c, length);
  sha_finalize(c, (u08)((msg_bit & masks[length]) | markbit[length]));
  return c->corrupt;
}

//
// SHA Get digest
static int sha_result(ctxs *c, u08 msg_dig[sha_hsh_sz]) {
  sha_error(c, msg_dig, 0, 2);
  if (!c->compute) sha_finalize(c, 0x80);
  for (int i = 0; i < sha_hsh_sz; ++i) {
    msg_dig[i] = (u08)(c->imh[i>>3] >> 8 * (7 - (i % 8)));
  }
  return sha_ok;
}

//
// SHA Check if hashvalue matches a predef hexstr and convert to str if s!=NULL
static int sha_match_to_str(cuc *hashvalue, cc *hexstr, int hashsize, char *s) {
  int j = 0, k, l;

  for (int i = 0; i < hashsize; ++i) {
    k = hexdigits[(hashvalue[i] >> 4) & 0xF]; l = hexdigits[hashvalue[i] & 0xF];
    if (s != NULL) {s[j++] = k; s[j++] = l; s[j]='\0';}
    if (*hexstr++ != k) return 0; if (*hexstr++ != l) return 0;
  }
  return 1;
}

//
// Create a SHA hash from string
void lighthash_hash_new(cc *in, char* s) {
  u08 *inn = malloc(sizeof(u08) * strlen(in)), msg_dig[sha_hsh_sz];
  ctxs sha;

  // Convert char* to uint8_t*
  for (unsigned long i = 0; i < strlen(in); i++) {inn[i] = (u08)in[i];}
  sha_reset(&sha);
  sha_input(&sha, inn, strlen(in));
  sha_final(&sha, (u08)0, 0);
  sha_result(&sha, msg_dig);
  // Convert uint8_t* to char*
  sha_match_to_str(msg_dig, s, 64, s);
  free(inn);
}

//
// HMAC error check
static int hmac_error(ctxh *c) {
  if (!c) return sha_null;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = sha_err;
  return sha_ok;
}

//
// HMAC initialize Context
static int hmac_reset(ctxh *c, cuc *key, int key_len) {
  b08 k_ipad[sha_blk_sz], tmp[sha_hsh_sz], blocksize, hashsize, ret;

  if (!c) return sha_null;
  c->compute = 0;
  c->corrupt = sha_ok;
  blocksize = c->blk_size = sha_blk_sz;
  hashsize = c->size = sha_hsh_sz;

  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    ctxs cc;
    ret = sha_reset(&cc)|| sha_input(&cc, key, key_len)|| sha_result(&cc, tmp);
    if (ret != sha_ok) return ret;
    key = tmp;
    key_len = hashsize;
  }

  // HMAC Transform
  for (int i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36; c->k_opad[i] = key[i] ^ 0x5c;
  }
  // Remaining pad bytes are '\0' XOR'd with ipad and opad values
  for (int i = key_len; i < blocksize; i++) {
    k_ipad[i] = 0x36; c->k_opad[i] = 0x5c;
  }
  return c->corrupt = sha_reset(&c->sha)||sha_input(&c->sha, k_ipad, blocksize);
}

//
// HMAC input
static int hmac_input(ctxh *c, cuc *text, int text_len) {
  hmac_error(c); return c->corrupt = sha_input(&c->sha, text, text_len);
}

//
// HMAC Add final bits
static int hmac_final(ctxh *c, u08 bits, ui bit_count) {
  hmac_error(c); return c->corrupt = sha_final(&c->sha, bits, bit_count);
}

//
// HMAC Get digest
static int hmac_result(ctxh *c, u08 *digest) {
  // Finish up 1st pass. Perform outer SHA, init context for 2nd pass.
  // Start with outer pad, then results of 1st hash. Finish up 2nd pass
  hmac_error(c);
  int ret = sha_result(&c->sha, digest) || sha_reset(&c->sha) ||
    sha_input(&c->sha, c->k_opad, c->blk_size) ||
    sha_input(&c->sha, digest, c->size) || sha_result(&c->sha, digest);
  c->compute = 1;
  return c->corrupt = ret;
}

//
// HMAC & SHA Test suite runner
int lighthash_hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs) {
  u08 msg_dig[sha_hsh_sz], err;
  ctxh hmac;
  ctxs sha;

  if (k) {err = hmac_reset(&hmac, k, kl);}
  else {err = sha_reset(&sha);}
  if (err != sha_ok) {return err;}

  for (int i = 0; i < r; ++i) {
    if (k) {err = hmac_input(&hmac, (cu8 *)ta, l);}
    else {err = sha_input(&sha, (cu8 *)ta, l);}
    if (err != sha_ok) {return err;}
  }

  if (neb > 0) {
    if (k) {err = hmac_final(&hmac, (u08)eb, neb);}
    else {err = sha_final(&sha, (u08)eb, neb);}
    if (err != sha_ok) {return err;}
  }

  if (k) {err = hmac_result(&hmac, msg_dig);}
  else {err = sha_result(&sha, msg_dig);}
  if (err != sha_ok) {return err;}
  return sha_match_to_str(msg_dig, ra, hs, NULL);
}

int lighthash_hash_test() {
  // 11 of 11 SHA tests pass
  for (int i = 0; (i <= TESTCOUNT - 1); ++i) {
    int err = lighthash_hash(h.t[i].testarray, h.t[i].length,
      h.t[i].repeatcount, h.t[i].nr_extrabits,
      h.t[i].extrabits, 0, 0, h.t[i].res_arr, h.hashsize);
    assert(err == 1); if (err != 1) return 0;
  }
  // 7 of 7 HMAC tests pass
  for (int i = 0; (i <= HMACTESTCOUNT-1); ++i) {
    cc *da = hm[i].dataarray[1] ? hm[i].dataarray[1] : hm[i].dataarray[0];
    int dl = hm[i].datalength[1] ? hm[i].datalength[1] : hm[i].datalength[0];
    cuc* ka = (cuc*)(hm[i].keyarray[1] ? hm[i].keyarray[1] : hm[i].keyarray[0]);
    int kl = hm[i].keylength[1] ? hm[i].keylength[1] : hm[i].keylength[0];
    int err = lighthash_hash(da, dl, 1, 0, 0, ka, kl, hm[i].res_arr[0], hm[i].res_len[0]);
    assert(err == 1); if (err != 1) return 0;
  }
  return 1;
}
