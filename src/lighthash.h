//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1

#include <stdint.h>

#ifndef SHA_DEFINES
#define SHA_DEFINES 1

// These constants hold size information for each of the SHA hashing operations
#define sha_blk_sz 128                           // SHA Message Block Size
#define sha_hsh_sz 64                            // SHA Hash Size
#define sha_hsh_sb 512                           // SHA Hash Size Bits

// All SHA functions return one of these values.
#define sha_ok 0                                 // Success
#define sha_null 1                               // Null pointer parameter
#define sha_itl 2                                // Input data too long
#define sha_err 3                                // State error
#define sha_bad 4                                // passed a bad parameter
#endif

// This structure will hold context information for the SHA hashing operation.
typedef struct ctxs {
  u64 imh[sha_hsh_sz / 8];                       // Intermediate Message Digest
  u64 len_hi, len_lo;                            // Message length in bits
  int_least16_t msg_blk_i;                       // Message_Block array index
  u08 mb[sha_blk_sz];                            // 1024-bit message blocks
  int compute;                                   // Is the hash computed?
  int corrupt;                                   // Cumulative corrupt code
} ctxs;

// This structure will hold context information for the HMAC keyed-hashing operation.
typedef struct ctxh {
  int which;                                     // Which SHA is being used
  int size;                                      // Hash size of SHA being used
  int blk_size;                                  // Block size of SHA being used
  ctxs sha;                                      // SHA Context
  b08 k_opad[sha_blk_sz];                        // Key XORd with opad
  int compute;                                   // Is the MAC computed?
  int corrupt;                                   // Cumulative corruption code
} ctxh;

// SHA Hashing (keeping the static ones as commented to get a overview)
// int sha_reset(ctxs *c);
// int sha_input(ctxs *c, cu8 *bytes, ui bytecount);
// int sha_final(ctxs *, u08 bits, ui bit_count);
// int sha_result(ctxs *c, u08 msg_dig[sha_hsh_sz]);
// int sha_match_to_str(cuc *hashvalue, cc *hexstr, int hashsize, char *s);

// HMAC Keyed-Hashing for Message Authentication, RFC 2104
// int hmac_reset(ctxh *c, cuc *key, int key_len);
// int hmac_input(ctxh *c, cuc *text,int text_len);
// int hmac_final(ctxh *c, u08 bits, ui bit_count);
// int hmac_result(ctxh *c, u08 digest[sha_hsh_sz]);

void lightssl_hash_new(cc *in, char* s);
int lightssl_hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs);
int lightssl_hash_test();
#endif
