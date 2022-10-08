//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef _LIGHTHASH_H_
#define _LIGHTHASH_H_

#include <stdint.h>

#ifndef _SHA_enum_
#define _SHA_enum_

//
// All SHA functions return one of these values.
enum {
  sha_ok = 0,                                    // Success
  sha_null,                                      // Null pointer parameter
  sha_itl,                                       // Input data too long
  sha_err,                                       // State error
  sha_bad                                        // passed a bad parameter
};
#endif

//
// These constants hold size information for each of the SHA hashing operations
enum {
  sha_blk_sz = 128,                              // SHA Message Block Size
  sha_hsh_sz = 64,                               // SHA Hash Size
  sha_hsh_sb = 512                               // SHA Hash Size Bits
};

//
// This structure will hold context information for the SHA hashing operation.
typedef struct shactx {
  u64 imh[sha_hsh_sz / 8];                       // Intermediate Message Digest
  u64 len_hi, len_lo;                            // Message length in bits
  int_least16_t msg_blk_i;                       // Message_Block array index
  u08 mb[sha_blk_sz];                            // 1024-bit message blocks
  int compute;                                   // Is the hash computed?
  int corrupt;                                   // Cumulative corrupt code
} shactx;

//
// This structure will hold context information for the HMAC keyed-hashing operation.
typedef struct hmacctx {
  int which;                                     // Which SHA is being used
  int size;                                      // Hash size of SHA being used
  int blk_size;                                  // Block size of SHA being used
  shactx shactx;                                 // SHA Context
  uc k_opad[sha_blk_sz];                         // Key XORd with opad
  int compute;                                   // Is the MAC computed?
  int corrupt;                                   // Cumulative corruption code
} hmacctx;

void sha_print(uint8_t *md, int hashsize, cc *resultarray);
int sha_reset(shactx *c);
int sha_input(shactx *c, const uint8_t *bytes, unsigned int bytecount);
int sha_final(shactx *, uint8_t bits, unsigned int bit_count);
int sha_result(shactx *c,uint8_t msg_dig[sha_hsh_sz]);
int sha_match(cuc *hashvalue, cc *hexstr, int hashsize);
int hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs);
void hash_new(const char *in, char* s);

//
// HMAC Keyed-Hashing for Message Authentication, RFC 2104, for all SHAs.
// This interface allows any length of text input to be used.
int hmac_reset(hmacctx *c, cuc *key, int key_len);
int hmac_input(hmacctx *c, cuc *text,int text_len);
int hmac_final(hmacctx *c, uint8_t bits, unsigned int bit_count);
int hmac_result(hmacctx *c, uint8_t digest[sha_hsh_sz]);

#endif
