//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "lighthash.h"
#include "lightdefs.h"

// Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5
const u64 h0[] = {
  0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
  0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
  0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179};
const u64 k0[80] = {
  0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
  0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
  0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
  0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
  0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
  0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
  0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
  0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
  0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
  0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
  0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
  0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
  0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
  0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
  0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
  0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
  0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
  0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
  0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
  0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
  0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
  0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
  0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
  0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
  0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
  0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
  0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817};
const u08 hexdigits[] = "0123456789ABCDEF";
const u08 masks[8]    = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE};
const u08 markbit[8]  = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

//
// SHA Process message block
static void lhash_sha_proc_msgblk(ctxs *c) {
  u64 A[8], W[80], t1, t2, t3 = 0;
  int t, t8;

  // Initialize the first 16 words in the array W
  for (t = t8 = 0; t < 16; t++, t8 += 8) {
    for (int i = 0; i < 8; i++) t3 |= ((u64)(c->mb[t8 + i]) << (56 - (i * 8)));
    W[t] = t3; t3 = 0;
  }
  for (t = 16; t < 80; t++) {
    W[t] = SHA_s1(W[t - 2]) + W[t - 7] + SHA_s0(W[t - 15]) + W[t - 16];
  }
  for (int i = 0; i < 8; i++) {A[i] = c->imh[i];}
  for (t = 0; t < 80; t++) {
    t1 = A[7] + SHA_S1(A[4]) + SHA_CH00(A[4],A[5],A[6]) + k0[t] + W[t];
    t2 = SHA_S0(A[0]) + SHA_MAJ0(A[0], A[1], A[2]);
    for (int i = 7; i >= 0; i--) {if (i != 4 && i != 0) {A[i] = A[i - 1];}
      else if (i == 4) {A[4] = A[3] + t1;}
      else if (i == 0) {A[0] = t1 + t2;}}
  }
  for (int i = 0; i < 8; i++) {c->imh[i] += A[i];}
  c->msg_blk_i = 0;
}

//
// SHA Pad message if needed. Process it. Cont pad 2nd block if needed.
static void lhash_sha_pad_msg(ctxs *c, u08 pad_byte) {
  if (c->msg_blk_i >= (SHA_BLK_SZ - 16)) {
    c->mb[c->msg_blk_i++] = pad_byte;
    while (c->msg_blk_i < SHA_BLK_SZ) c->mb[c->msg_blk_i++] = 0;
    lhash_sha_proc_msgblk(c);
  } else c->mb[c->msg_blk_i++] = pad_byte;
  while (c->msg_blk_i < (SHA_BLK_SZ - 16)) {c->mb[c->msg_blk_i++] = 0;}
  for (int i = 0; i < 8; i++) c->mb[112 + i] = (u08)(c->len_hi >> (56 - (i*8)));
  for (int i = 0; i < 8; i++) c->mb[120 + i] = (u08)(c->len_lo >> (56 - (i*8)));
  lhash_sha_proc_msgblk(c);
}

//
// SHA Finalize
static void lhash_sha_finalize(ctxs *c, u08 pad_byte) {
  lhash_sha_pad_msg(c, pad_byte);
  // Clear message
  for (int_least16_t i = 0; i < SHA_BLK_SZ; ++i) {c->mb[i] = 0;}
  c->len_hi = c->len_lo = 0;
  c->compute = 1;
}

//
// SHA Error check
static int lhash_sha_error(ctxs *c, cu8 *msg_arr, ui length, int b) {
  if (!c) return SHA_NULL;
  if (!length) return SHA_OK;
  if (!msg_arr && b == 0) return SHA_NULL;
  if (c->compute) return c->corrupt = SHA_ERR;
  if (c->corrupt) return c->corrupt;
  if (length >= 8 && b == 1) return c->corrupt = SHA_BAD;
  return SHA_OK;
}

//
// SHA Clear
int lhash_sha_reset(ctxs *c) {
  if (!c) return SHA_NULL;
  c->msg_blk_i = 0;
  c->len_hi = c->len_lo = 0;
  c->compute = 0;
  c->corrupt = SHA_OK;
  for (int i = 0; i < SHA_HSH_SZ / 8; i++) {c->imh[i] = h0[i];}
  return SHA_OK;
}

//
// SHA Input
int lhash_sha_input(ctxs *c, cu8 *msg_arr, ui length) {
  lhash_sha_error(c, msg_arr, length, 0);
  while (length--) {
    c->mb[c->msg_blk_i++] = *msg_arr;
    if ((SHA_ADDL(c, 8) == SHA_OK) && (c->msg_blk_i == SHA_BLK_SZ))
      lhash_sha_proc_msgblk(c);
    msg_arr++;
  }
  return c->corrupt;
}

//
// SHA Add final bits
int lhash_sha_final(ctxs *c, u08 msg_bit, ui length) {
  lhash_sha_error(c, (cu8 *)0, length, 1);
  SHA_ADDL(c, length);
  lhash_sha_finalize(c, (u08)((msg_bit & masks[length]) | markbit[length]));
  return c->corrupt;
}

//
// SHA Get digest
int lhash_sha_result(ctxs *c, u08 msg_dig[SHA_HSH_SZ]) {
  lhash_sha_error(c, msg_dig, 0, 2);
  if (!c->compute) lhash_sha_finalize(c, 0x80);
  for (int i = 0; i < SHA_HSH_SZ; ++i) {
    msg_dig[i] = (u08)(c->imh[i>>3] >> 8 * (7 - (i % 8)));
  }
  return SHA_OK;
}

//
// SHA Check if hashvalue matches a predef hexstr and convert to str if s!=NULL
int lhash_sha_match_to_str(cuc *hashvalue, cc *hexstr, int hashsize, char *s) {
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
void lhash_hash_new(cc *in, char* s) {
  u08 msg_dig[SHA_HSH_SZ], inn[strlen(in)];
  ctxs sha;

  // Convert char* to uint8_t*
  for (u64 i = 0; i < strlen(in); i++) {inn[i] = (u08)in[i];}
  lhash_sha_reset(&sha);
  lhash_sha_input(&sha, inn, strlen(in));
  lhash_sha_final(&sha, (u08)0, 0);
  lhash_sha_result(&sha, msg_dig);
  // Convert uint8_t* to char*
  lhash_sha_match_to_str(msg_dig, s, 64, s);
}

//
// HMAC error check
static int lhash_hmac_error(ctxh *c) {
  if (!c) return SHA_NULL;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = SHA_ERR;
  return SHA_OK;
}

//
// HMAC initialize Context
int lhash_hmac_reset(ctxh *c, cuc *key, int key_len) {
  b08 k_ipad[SHA_BLK_SZ], tmp[SHA_HSH_SZ], blocksize, hashsize, ret;

  if (!c) return SHA_NULL;
  c->compute = 0;
  c->corrupt = SHA_OK;
  blocksize = c->blk_size = SHA_BLK_SZ;
  hashsize = c->size = SHA_HSH_SZ;

  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    ctxs ct;
    ret = lhash_sha_reset(&ct) || lhash_sha_input(&ct, key, key_len) ||
      lhash_sha_result(&ct, tmp);
    if (ret != SHA_OK) return ret;
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
  return c->corrupt = lhash_sha_reset(&c->sha) ||
    lhash_sha_input(&c->sha, k_ipad, blocksize);
}

//
// HMAC input
int lhash_hmac_input(ctxh *c, cuc *text, int text_len) {
  lhash_hmac_error(c);
  return c->corrupt = lhash_sha_input(&c->sha, text, text_len);
}

//
// HMAC Add final bits
int lhash_hmac_final(ctxh *c, u08 bits, ui bit_count) {
  lhash_hmac_error(c);
  return c->corrupt = lhash_sha_final(&c->sha, bits, bit_count);
}

//
// HMAC Get digest
int lhash_hmac_result(ctxh *c, u08 *digest) {
  // Finish up 1st pass. Perform outer SHA, init context for 2nd pass.
  // Start with outer pad, then results of 1st hash. Finish up 2nd pass
  lhash_hmac_error(c);
  int ret = lhash_sha_result(&c->sha, digest) || lhash_sha_reset(&c->sha) ||
    lhash_sha_input(&c->sha, c->k_opad, c->blk_size) ||
    lhash_sha_input(&c->sha, digest, c->size)||lhash_sha_result(&c->sha, digest);
  c->compute = 1;
  return c->corrupt = ret;
}

//
// HMAC & SHA Test suite runner
int lhash_hash(cc *ta, int l, u64 r, int n, int eb, cuc *k, int kl, cc *ra, int hs) {
  u08 msg_dig[SHA_HSH_SZ], err;
  ctxh hmac; ctxs sha;

  if (k) {
    err = lhash_hmac_reset(&hmac, k, kl); if (err != SHA_OK) {return err;}
    for (u64 i = 0; i < r; ++i) {err = lhash_hmac_input(&hmac, (cu8 *)ta, l);
      if (err != SHA_OK) {return err;}}
    if (n > 0) {err = lhash_hmac_final(&hmac, (u08)eb, n);
      if (err != SHA_OK) {return err;}}
    err = lhash_hmac_result(&hmac, msg_dig); if (err != SHA_OK) {return err;}
  } else {
    err = lhash_sha_reset(&sha); if (err != SHA_OK) {return err;}
    for (u64 i = 0; i < r; ++i) {err = lhash_sha_input(&sha, (cu8 *)ta, l);
      if (err != SHA_OK) {return err;}}
    if (n > 0) {err = lhash_sha_final(&sha, (u08)eb, n);
      if (err != SHA_OK) {return err;}}
    err = lhash_sha_result(&sha, msg_dig); if (err != SHA_OK) {return err;}
  }
  return lhash_sha_match_to_str(msg_dig, ra, hs, NULL);
/*
  if (k) {err = lhash_hmac_reset(&hmac, k, kl);}
  else {err = lhash_sha_reset(&sha);}
  if (err != SHA_OK) {return err;}

  for (u64 i = 0; i < r; ++i) {
    if (k) {err = lhash_hmac_input(&hmac, (cu8 *)ta, l);}
    else {err = lhash_sha_input(&sha, (cu8 *)ta, l);}
    if (err != SHA_OK) {return err;}
  }

  if (n > 0) {
    if (k) {err = lhash_hmac_final(&hmac, (u08)eb, n);}
    else {err = lhash_sha_final(&sha, (u08)eb, n);}
    if (err != SHA_OK) {return err;}
  }

  if (k) {err = lhash_hmac_result(&hmac, msg_dig);}
  else {err = lhash_sha_result(&sha, msg_dig);}
  if (err != SHA_OK) {return err;}
  return lhash_sha_match_to_str(msg_dig, ra, hs, NULL);
*/
}
