//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include "sha.h"

//
// Compute a HMAC message digest
int hmac(const unsigned char *message_array, int length, const unsigned char *key,
  int key_len, uint8_t digest[SHA512HashSize]) {
  HMACContext c;

  return hmacReset(&c, key, key_len) ||
    hmacInput(&c, message_array, length) || hmacResult(&c, digest);
}

//
// initialize the hmacContext
int hmacReset(HMACContext *c, const unsigned char *key, int key_len) {
  int blocksize, hashsize, ret;
  unsigned char k_ipad[SHA512_Message_Block_Size];
  unsigned char tempkey[SHA512HashSize];

  if (!c) return shaNull;
  c->Computed = 0;
  c->Corrupted = shaSuccess;
  blocksize = c->blockSize = SHA512_Message_Block_Size;
  hashsize = c->hashSize = SHA512HashSize;

  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    SHA512Context cc;
    int err = SHA512Reset((SHA512Context*)&cc) ||
      SHA512Input((SHA512Context*)&cc, key, key_len) ||
      SHA512Result((SHA512Context*)&cc, tempkey);
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

  ret = SHA512Reset((SHA512Context*)&c->shaContext) ||
    SHA512Input((SHA512Context*)&c->shaContext, k_ipad, blocksize);
  return c->Corrupted = ret;
}

//
//
int hmacInput(HMACContext *c, const unsigned char *text, int text_len) {
  if (!c) return shaNull;
  if (c->Corrupted) return c->Corrupted;
  if (c->Computed) return c->Corrupted = shaStateError;
  return c->Corrupted =
    SHA512Input((SHA512Context*)&c->shaContext, text, text_len);
}

//
// Add final bits
int hmacFinalBits(HMACContext *c, uint8_t bits, unsigned int bit_count) {
  if (!c) return shaNull;
  if (c->Corrupted) return c->Corrupted;
  if (c->Computed) return c->Corrupted = shaStateError;
  return c->Corrupted =
    SHA512FinalBits((SHA512Context*)&c->shaContext, bits,bit_count);
}

//
// Get the hmac digest
int hmacResult(HMACContext *c, uint8_t *digest) {
  int ret;
  if (!c) return shaNull;
  if (c->Corrupted) return c->Corrupted;
  if (c->Computed) return c->Corrupted = shaStateError;

  // finish up 1st pass
  // perform outer SHA, init context for 2nd pass
  // start with outer pad
  // then results of 1st hash
  //finish up 2nd pass
  ret = SHA512Result((SHA512Context*)&c->shaContext, digest) ||
    SHA512Reset((SHA512Context*)&c->shaContext) ||
    SHA512Input((SHA512Context*)&c->shaContext, c->k_opad, c->blockSize) ||
    SHA512Input((SHA512Context*)&c->shaContext, digest, c->hashSize) ||
    SHA512Result((SHA512Context*)&c->shaContext, digest);

  c->Computed = 1;
  return c->Corrupted = ret;
}
