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
  (++c->len_hi == 0) ? shaInputTooLong : (c)->corrupt)

#ifndef _SHA_enum_
#define _SHA_enum_

//
// All SHA functions return one of these values.
enum {
  shaSuccess = 0,
  shaNull,         // Null pointer parameter
  shaInputTooLong, // input data too long
  shaStateError,   // called Input after FinalBits or Result
  shaBadParam      // passed a bad parameter
};
#endif

//
// These constants hold size information for each of the SHA hashing operations
enum {
  shaMsgBlockSize = 128,
  shaHashSize = 64,
  shaHashSizeBits = 512
};

//
// This structure will hold context information for the SHA-512 hashing operation.
typedef struct shactx {
  uint64_t imh[shaHashSize / 8];                 // Intermediate Message Digest
  uint64_t len_hi, len_lo;                 // Message length in bits
  int_least16_t msg_blk_i;                // Message_Block array index
  uint8_t mb[shaMsgBlockSize];            // 1024-bit message blocks
  int compute;                                     // Is the hash computed?
  int corrupt;                                    // Cumulative corrupt code
} shactx;

//
// This structure will hold context information for the HMAC keyed-hashing operation.
typedef struct hmacctx {
  int whichSha;                                  // which SHA is being used
  int hashSize;                                  // hash size of SHA being used
  int blockSize;                                 // block size of SHA being used
  shactx shactx;
  uc k_opad[shaMsgBlockSize]; // key XORd with opad
  int compute;                                  // Is the MAC computed?
  int corrupt;                                 // Cumulative corruption code
} hmacctx;

void sha_print(uint8_t *md, int hashsize, cc *resultarray);
int sha_reset(shactx *c);
int sha_input(shactx *c, const uint8_t *bytes, unsigned int bytecount);
int sha_final(shactx *, uint8_t bits, unsigned int bit_count);
int sha_result(shactx *c,uint8_t msg_dig[shaHashSize]);
int sha_match(cuc *hashvalue, cc *hexstr, int hashsize);
int hash(cc *ta, int l, long r,int neb, int eb, cuc *k,int kl, cc *ra, int hs);

//
// HMAC Keyed-Hashing for Message Authentication, RFC 2104, for all SHAs.
// This interface allows a fixed-length text input to be used.
extern int hmac(
  cuc *text,       // pointer to data stream
  int text_len,                    // length of data stream
  cuc *key,        // pointer to authentication key
  int key_len,                     // length of authentication key
  uint8_t digest[shaHashSize]); // caller digest to fill in

//
// HMAC Keyed-Hashing for Message Authentication, RFC 2104, for all SHAs.
// This interface allows any length of text input to be used.
int hmac_reset(hmacctx *c, const unsigned char *key, int key_len);
int hmac_input(hmacctx *c, const unsigned char *text,int text_len);
int hmac_final(hmacctx *c, uint8_t bits, unsigned int bit_count);
int hmac_result(hmacctx *c, uint8_t digest[shaHashSize]);

#endif
