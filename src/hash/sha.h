//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#ifndef _SHA_H_
#define _SHA_H_

#include <stdint.h>

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
  SHA512_Message_Block_Size = 128,
  SHA512HashSize = 64,
  SHA512HashSizeBits = 512
};

//
// This structure will hold context information for the SHA-512 hashing operation.
typedef struct SHA512Context {
  uint64_t Intermediate_Hash[SHA512HashSize / 8];   // Message Digest
  uint64_t Length_High, Length_Low;                 // Message length in bits
  int_least16_t Message_Block_Index;                // Message_Block array index
  uint8_t Message_Block[SHA512_Message_Block_Size]; // 1024-bit message blocks
  int Computed;                                     // Is the hash computed?
  int Corrupted;                                    // Cumulative corrupt code
} SHA512Context;

//
// This structure will hold context information for the HMAC keyed-hashing operation.
typedef struct HMACContext {
  int whichSha;                                  // which SHA is being used
  int hashSize;                                  // hash size of SHA being used
  int blockSize;                                 // block size of SHA being used
  SHA512Context shaContext;
  unsigned char k_opad[SHA512_Message_Block_Size]; // key XORd with opad
  int Computed;                                  // Is the MAC computed?
  int Corrupted;                                 // Cumulative corruption code
} HMACContext;

int SHA512Reset(SHA512Context *context);
int SHA512Input(SHA512Context *, const uint8_t *bytes, unsigned int bytecount);
int SHA512FinalBits(SHA512Context *, uint8_t bits, unsigned int bit_count);
int SHA512Result(SHA512Context *,uint8_t Message_Digest[SHA512HashSize]);

//
// HMAC Keyed-Hashing for Message Authentication, RFC 2104, for all SHAs.
// This interface allows a fixed-length text input to be used.
extern int hmac(
  const unsigned char *text,       // pointer to data stream
  int text_len,                    // length of data stream
  const unsigned char *key,        // pointer to authentication key
  int key_len,                     // length of authentication key
  uint8_t digest[SHA512HashSize]); // caller digest to fill in

//
// HMAC Keyed-Hashing for Message Authentication, RFC 2104, for all SHAs.
// This interface allows any length of text input to be used.
extern int hmacReset(HMACContext *context,const unsigned char *key, int key_len);
extern int hmacInput(HMACContext *context, const unsigned char *text,int text_len);
extern int hmacFinalBits(HMACContext *context, uint8_t bits, unsigned int bit_count);
extern int hmacResult(HMACContext *context, uint8_t digest[SHA512HashSize]);
#endif
