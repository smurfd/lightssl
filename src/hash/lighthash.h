//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef _LIGHTHASH_H_
#define _LIGHTHASH_H_

#include <stdint.h>

typedef const char cc;
typedef const unsigned char cuc;
typedef unsigned char uc;
typedef uint8_t  u08;
typedef uint64_t u64;

#define SHA_Ch(x, y, z)    (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)   (((x) & ((y) | (z))) | ((y) & (z)))
#define SHA_Parity(x, y, z) ((x) ^  (y) ^ (z))

// Define the SHA shift, rotate left and rotate right macros
#define SHA_SHRI(b,w)  (((u64)(w)) >> (b))
#define SHA_ROTR(b,w) ((((u64)(w)) >> (b)) | (((u64)(w)) << (64-(b))))

// Define the SHA SIGMA and sigma macros
#define SHA_S0(w) (SHA_ROTR(28,w) ^ SHA_ROTR(34,w) ^ SHA_ROTR(39,w))
#define SHA_S1(w) (SHA_ROTR(14,w) ^ SHA_ROTR(18,w) ^ SHA_ROTR(41,w))
#define SHA_s0(w) (SHA_ROTR( 1,w) ^ SHA_ROTR( 8,w) ^ SHA_SHRI( 7,w))
#define SHA_s1(w) (SHA_ROTR(19,w) ^ SHA_ROTR(61,w) ^ SHA_SHRI( 6,w))

// Add "length" to the length. Set Corrupted when overflow has occurred.
#define SHA_AddLength(c, l, t)(t = c->len_lo,\
  c->corrupt = ((c->len_lo += l) < t) &&\
  (++c->len_hi == 0) ? sha_itl : (c)->corrupt)

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
  int which;                                  // Which SHA is being used
  int size;                                  // Hash size of SHA being used
  int blk_size;                                 // Block size of SHA being used
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

//
// HMAC Keyed-Hashing for Message Authentication, RFC 2104, for all SHAs.
// This interface allows any length of text input to be used.
int hmac_reset(hmacctx *c, cuc *key, int key_len);
int hmac_input(hmacctx *c, cuc *text,int text_len);
int hmac_final(hmacctx *c, uint8_t bits, unsigned int bit_count);
int hmac_result(hmacctx *c, uint8_t digest[sha_hsh_sz]);

#endif
