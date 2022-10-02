//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include "sha.h"

//
// Compute a HMAC message digest
int hmac(const unsigned char *message_array, int length, const unsigned char *key,
  int key_len, uint8_t digest[SHA512HashSize]) {
  HMACContext context;

  return hmacReset(&context, key, key_len) ||
    hmacInput(&context, message_array, length) || hmacResult(&context, digest);
}

//
// initialize the hmacContext
int hmacReset(HMACContext *context, const unsigned char *key, int key_len) {
  int i, blocksize, hashsize, ret;
  unsigned char k_ipad[SHA512_Message_Block_Size];
  unsigned char tempkey[SHA512HashSize];

  if (!context) return shaNull;
  context->Computed = 0;
  context->Corrupted = shaSuccess;
  blocksize = context->blockSize = SHA512_Message_Block_Size;
  hashsize = context->hashSize = SHA512HashSize;

  // If key is longer than the hash blocksize, reset it to key = HASH(key).
  if (key_len > blocksize) {
    SHA512Context tcontext;
    int err = SHA512Reset((SHA512Context*)&context) ||
              SHA512Input((SHA512Context*)&context, key, key_len) ||
              SHA512Result((SHA512Context*)&context, tempkey);
    if (err != shaSuccess) return err;

    key = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key, 0-padded to a total of blocksize bytes,
   * ipad is the byte 0x36 repeated blocksize times,
   * opad is the byte 0x5c repeated blocksize times,
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    context->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < blocksize; i++) {
    k_ipad[i] = 0x36;
    context->k_opad[i] = 0x5c;
  }
  ret = SHA512Reset((SHA512Context*)&context->shaContext) ||
    SHA512Input((SHA512Context*)&context->shaContext, k_ipad, blocksize);
  return context->Corrupted = ret;
}

//
//
int hmacInput(HMACContext *context, const unsigned char *text, int text_len) {
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  return context->Corrupted =
    SHA512Input((SHA512Context*)&context->shaContext, text, text_len);
}

//
// Add final bits
int hmacFinalBits(HMACContext *context, uint8_t bits, unsigned int bit_count) {
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  return context->Corrupted =
    SHA512FinalBits((SHA512Context*)&context->shaContext, bits,bit_count);
}

//
// Get the hmac digest
int hmacResult(HMACContext *context, uint8_t *digest) {
  int ret;
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  ret = SHA512Result((SHA512Context*)&context->shaContext, digest) ||
         /* perform outer SHA */
         /* init context for 2nd pass */
    SHA512Reset((SHA512Context*)&context->shaContext) ||
         /* start with outer pad */
    SHA512Input((SHA512Context*)&context->shaContext, context->k_opad, context->blockSize) ||
         /* then results of 1st hash */
    SHA512Input((SHA512Context*)&context->shaContext, digest, context->hashSize) ||
         /* finish up 2nd pass */
    SHA512Result((SHA512Context*)&context->shaContext, digest);

  context->Computed = 1;
  return context->Corrupted = ret;
}