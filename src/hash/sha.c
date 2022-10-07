//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include <stdio.h>
#include <string.h>
#include "sha.h"

// Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5
static u64 SHA_H0[] = {
  0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
  0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
  0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179};

// 0b00000000 0b10000000 0b11000000 0b11100000 0b11110000 0b11111000
// 0b11111100 0b11111110
// 0b10000000 0b01000000 0b00100000 0b00010000 0b00001000 0b00000100
// 0b00000010 0b00000001
static u08 masks[8]   = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE};
static u08 markbit[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

static const u64 SHA_K[80] = {
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

//
//
int sha_reset(shactx *c) {
  if (!c) return shaNull;
  c->msg_blk_i = 0;
  c->len_hi = c->len_lo = 0;

  for (int i = 0; i < shaHashSize / 8; i++) c->imh[i] = SHA_H0[i];
  c->compute = 0;
  c->corrupt = shaSuccess;

  return shaSuccess;
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
int sha_input(shactx *c, const u08 *message_array,
  unsigned int length) {
  uint64_t tmp;

  if (!c) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (c->compute) return c->corrupt = shaStateError;
  if (c->corrupt) return c->corrupt;

  while (length--) {
    c->mb[c->msg_blk_i++] = *message_array;
    if ((SHA_AddLength(c, 8, tmp) == shaSuccess) &&
      (c->msg_blk_i == shaMsgBlockSize))
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
  if (c->msg_blk_i >= (shaMsgBlockSize-16)) {
    c->mb[c->msg_blk_i++] = pad_byte;
    while (c->msg_blk_i < shaMsgBlockSize)
      c->mb[c->msg_blk_i++] = 0;

    sha_proc_msgblk(c);
  } else c->mb[c->msg_blk_i++] = pad_byte;

  while (c->msg_blk_i < (shaMsgBlockSize-16)) c->mb[c->msg_blk_i++] = 0;

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
  for (int_least16_t i = 0; i < shaMsgBlockSize; ++i) c->mb[i] = 0;

  c->len_hi = c->len_lo = 0;
  c->compute = 1;
}

//
//
int sha_final(shactx *c, u08 msg_bit, unsigned int length) {
  uint64_t tmp;

  if (!c) return shaNull;
  if (!length) return shaSuccess;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = shaStateError;
  if (length >= 8) return c->corrupt = shaBadParam;

  SHA_AddLength(c, length, tmp);
  sha_finalize(c, (u08)((msg_bit & masks[length]) | markbit[length]));

  return c->corrupt;
}

//
//
int sha_result(shactx *c, u08 msg_dig[shaHashSize]) {
  if (!c) return shaNull;
  if (!msg_dig) return shaNull;
  if (c->corrupt) return c->corrupt;
  if (!c->compute) sha_finalize(c, 0x80);

  for (int i = 0; i < shaHashSize; ++i)
    msg_dig[i] = (u08)(c->imh[i>>3] >> 8 * (7 - (i % 8)));

  return shaSuccess;
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
  uint8_t msg_dig[shaHashSize];
  shactx sha;
  hmacctx hmac;
  int err;

  memset(&sha, '\343', sizeof(sha)); // force bad data into struct
  memset(&hmac, '\343', sizeof(hmac));

  if (k) {err = hmac_reset(&hmac, k, kl);}
  else {err = sha_reset((shactx*)&sha);}
  if (err != shaSuccess) {return err;}

  for (int i = 0; i < r; ++i) {
    if (k) {err = hmac_input(&hmac, (const uint8_t *)ta, l);}
    else {err = sha_input((shactx*)&sha, (const uint8_t *)ta, l);}
    if (err != shaSuccess) {return err;}
  }

  if (neb > 0) {
    if (k) {hmac_final(&hmac, (uint8_t)eb, neb);}
    else {sha_final((shactx*)&sha, (uint8_t)eb, neb);}
    if (err != shaSuccess) {return err;}
  }

  if (k) {err = hmac_result(&hmac, msg_dig);}
  else {err = sha_result((shactx*)&sha, msg_dig);}
  if (err != shaSuccess) {return err;}
  //sha_print(msg_dig, hs, ra);

  return sha_match(msg_dig, ra, hs);
}

// HMAC

//
// Compute a HMAC message digest
int hmac(const unsigned char *msg_arr, int length, const unsigned char *key,
  int key_len, uint8_t digest[shaHashSize]) {
  hmacctx c;

  return hmac_reset(&c, key, key_len) ||
    hmac_input(&c, msg_arr, length) || hmac_result(&c, digest);
}

//
// initialize the hmacctx
int hmac_reset(hmacctx *c, cuc *key, int key_len) {
  int blocksize, hashsize, ret;
  uc k_ipad[shaMsgBlockSize];
  uc tempkey[shaHashSize];

  if (!c) return shaNull;
  c->compute = 0;
  c->corrupt = shaSuccess;
  blocksize = c->blockSize = shaMsgBlockSize;
  hashsize = c->hashSize = shaHashSize;

  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    shactx cc;
    int err = sha_reset((shactx*)&cc) ||
      sha_input((shactx*)&cc, key, key_len) ||
      sha_result((shactx*)&cc, tempkey);
    if (err != shaSuccess) return err;

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
int hmac_input(hmacctx *c, const unsigned char *text, int text_len) {
  if (!c) return shaNull;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = shaStateError;
  return c->corrupt = sha_input((shactx*)&c->shactx, text, text_len);
}

//
// Add final bits
int hmac_final(hmacctx *c, uint8_t bits, unsigned int bit_count) {
  if (!c) return shaNull;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = shaStateError;
  return c->corrupt = sha_final((shactx*)&c->shactx, bits,bit_count);
}

//
// Get the hmac digest
int hmac_result(hmacctx *c, uint8_t *digest) {
  int ret;
  if (!c) return shaNull;
  if (c->corrupt) return c->corrupt;
  if (c->compute) return c->corrupt = shaStateError;

  // finish up 1st pass
  // perform outer SHA, init context for 2nd pass
  // start with outer pad
  // then results of 1st hash
  // finish up 2nd pass
  ret = sha_result((shactx*)&c->shactx, digest) ||
    sha_reset((shactx*)&c->shactx) ||
    sha_input((shactx*)&c->shactx, c->k_opad, c->blockSize) ||
    sha_input((shactx*)&c->shactx, digest, c->hashSize) ||
    sha_result((shactx*)&c->shactx, digest);

  c->compute = 1;
  return c->corrupt = ret;
}
