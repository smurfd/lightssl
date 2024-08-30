// Auth: smurfd 2024
#ifndef LIGHTAES_H
#define LIGHTAES_H 1
#include <inttypes.h>
#include <string.h>
#include <stdint.h>

#define u64 unsigned long long int // because linux uint64_t is not same as on mac
typedef struct {
  int mode;           // 1 for Encryption, 0 for Decryption
  int rounds;         // keysize-based rounds count
  uint32_t *rk;       // pointer to current round key
  uint32_t buf[68];   // key expansion buffer
} aes_context;

typedef struct {
  int mode;               // cipher direction: encrypt/decrypt
  u64 len;           // cipher data length processed so far
  u64 add_len;       // total add data length
  u64 HL[16];        // precalculated lo-half HTable
  u64 HH[16];        // precalculated hi-half HTable
  uint8_t base_ectr[16];    // first counter-mode cipher output for tag
  uint8_t y[16];            // the current cipher-input IV|Counter value
  uint8_t buf[16];          // buf working value
  aes_context aes_ctx;    // cipher context used
} gcm_context;

typedef struct {
  uint8_t b[256]; // substitution box
  uint32_t T0[256], T1[256], T2[256], T3[256]; // key schedule assembly tables
} box;

typedef struct {
  uint8_t *key, *iv, *aad, *pt, *ct, *tag, *input, *output;
  size_t key_len, iv_len, aad_len, pt_len, ct_len, tag_len, length;
} ctx_param;

static const u64 last4[16] = {0x0000,0x1c20,0x3840,0x2460,0x7080,0x6ca0,0x48c0,0x54e0,0xe100,0xfd20,0xd940,0xc560,0x9180,0x8da0,0xa9c0,0xb5e0};

#define ENCRYPT 1
#define DECRYPT 0
#define GCM_AUTH_FAILURE 0x55555555
#define GET_UINT32_LE(n,b,i) {n = ((uint32_t)b[(i)]) | ((uint32_t)b[(i) + 1] << 8) | ((uint32_t)b[(i) + 2] << 16) | ((uint32_t)b[(i) + 3] << 24);}
#define PUT_UINT32_LE(n,b,i) {b[(i)]=(uint8_t)((n)); b[(i) + 1]=(uint8_t)((n) >> 8);b[(i) + 2]=(uint8_t)((n) >> 16); b[(i) + 3]=(uint8_t)((n) >> 24);}
#define GET_UINT32_BE(n,b,i) {n = ((uint32_t)b[(i)] << 24) | ((uint32_t)b[(i) + 1] << 16) | ((uint32_t)b[(i) + 2] << 8) | ((uint32_t)b[(i) + 3]);}
#define PUT_UINT32_BE(n,b,i) {b[(i)]=(uint8_t)((n) >> 24);b[(i) + 1]=(uint8_t)((n) >> 16);b[(i) + 2]=(uint8_t)((n) >> 8);b[(i) + 3] = (uint8_t)((n));}

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3) { \
  X0 = *RK++ ^ fsb.T0[(Y0) & 0xFF] ^ fsb.T1[(Y1 >> 8) & 0xFF] ^ fsb.T2[(Y2 >> 16) & 0xFF] ^ fsb.T3[(Y3 >> 24) & 0xFF]; \
  X1 = *RK++ ^ fsb.T0[(Y1) & 0xFF] ^ fsb.T1[(Y2 >> 8) & 0xFF] ^ fsb.T2[(Y3 >> 16) & 0xFF] ^ fsb.T3[(Y0 >> 24) & 0xFF]; \
  X2 = *RK++ ^ fsb.T0[(Y2) & 0xFF] ^ fsb.T1[(Y3 >> 8) & 0xFF] ^ fsb.T2[(Y0 >> 16) & 0xFF] ^ fsb.T3[(Y1 >> 24) & 0xFF]; \
  X3 = *RK++ ^ fsb.T0[(Y3) & 0xFF] ^ fsb.T1[(Y0 >> 8) & 0xFF] ^ fsb.T2[(Y1 >> 16) & 0xFF] ^ fsb.T3[(Y2 >> 24) & 0xFF]; \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3) { \
  X0 = *RK++ ^ rsb.T0[(Y0) & 0xFF] ^ rsb.T1[(Y3 >> 8) & 0xFF] ^ rsb.T2[(Y2 >> 16) & 0xFF] ^ rsb.T3[(Y1 >> 24) & 0xFF]; \
  X1 = *RK++ ^ rsb.T0[(Y1) & 0xFF] ^ rsb.T1[(Y0 >> 8) & 0xFF] ^ rsb.T2[(Y3 >> 16) & 0xFF] ^ rsb.T3[(Y2 >> 24) & 0xFF]; \
  X2 = *RK++ ^ rsb.T0[(Y2) & 0xFF] ^ rsb.T1[(Y1 >> 8) & 0xFF] ^ rsb.T2[(Y0 >> 16) & 0xFF] ^ rsb.T3[(Y3 >> 24) & 0xFF]; \
  X3 = *RK++ ^ rsb.T0[(Y3) & 0xFF] ^ rsb.T1[(Y2 >> 8) & 0xFF] ^ rsb.T2[(Y1 >> 16) & 0xFF] ^ rsb.T3[(Y0 >> 24) & 0xFF]; \
}

#define ROTL8(x) ((x << 8) & 0xFFFFFFFF) | (x >> 24)
#define XTIME(x) ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00))
#define MUL(x,y) ((x && y) ? pow[(log[x]+log[y]) % 255] : 0)
#define MIX(x,y) {y = ((y << 1) | (y >> 7)) & 0xFF; x ^= y;}
#define MIX4(x, y) {MIX(x, y); MIX(x, y); MIX(x, y); MIX(x, y);}
#define CPY128(RK,SK) {*RK++ = *SK++; *RK++ = *SK++; *RK++ = *SK++; *RK++ = *SK++;}
#define ROUND(r, S, A0, A1, A2, A3, B0, B1, B2, B3) {\
  r = ((uint32_t)S[A0 & 0xFF] << B0) ^ \
      ((uint32_t)S[A1 & 0xFF] << B1) ^ \
      ((uint32_t)S[A2 & 0xFF] << B2) ^ \
      ((uint32_t)S[A3 & 0xFF] << B3);}


// AES
void aes_init_keygen_tables(void);
int aes_setkey(aes_context *c, uint8_t mode, const uint8_t *key, uint8_t kz);
int aes_cipher(aes_context *ctx, const uint8_t input[16], uint8_t output[16]); // 128-bit in/out block

// GCM
int gcm_initialize(void);
int gcm_setkey(gcm_context *ctx, const uint8_t *key, const uint32_t keysize); // keysize in bytes (must be 16, 24, 32 for 128, 192 or 256-bit keys)
int gcm_crypt_and_tag(gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len, const uint8_t *add, size_t add_len, const uint8_t *input,
  uint8_t *output, size_t length, uint8_t *tag, size_t tag_len);
int gcm_auth_decrypt(gcm_context *ctx, const uint8_t *iv, size_t iv_len, const uint8_t *add, size_t add_len, const uint8_t *input, uint8_t *output,
  size_t length, const uint8_t *tag, size_t tag_len);
int gcm_start(gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len, const uint8_t *add, size_t add_len);
int gcm_update(gcm_context *ctx, size_t length, const uint8_t *input, uint8_t *output);
int gcm_finish(gcm_context *ctx, uint8_t *tag, size_t tag_len);
void gcm_zero_ctx(gcm_context *ctx);

// AES GCM
int aes_gcm_encrypt(uint8_t* out, const uint8_t* in, int in_len, const uint8_t* key, const size_t key_len, const uint8_t * iv, const size_t iv_len);
int aes_gcm_decrypt(uint8_t* out, const uint8_t* in, int in_len, const uint8_t* key, const size_t key_len, const uint8_t * iv, const size_t iv_len);

// AES GCM Test functions
int verify_gcm(uint8_t *vd);
int load_file_into_ram(const char *filename, uint8_t **result);
#endif
